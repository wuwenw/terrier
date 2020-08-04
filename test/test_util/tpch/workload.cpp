#include "test_util/tpch/workload.h"

#include "execution/compiler/compilation_context.h"

#include <random>

#include "common/managed_pointer.h"
#include "execution/compiler/output_schema_util.h"
#include "execution/exec/execution_context.h"
#include "execution/execution_util.h"
#include "execution/sql/value_util.h"
#include "execution/table_generator/table_generator.h"
#include "main/db_main.h"
#include "planner/plannodes/aggregate_plan_node.h"
#include "planner/plannodes/hash_join_plan_node.h"
#include "planner/plannodes/nested_loop_join_plan_node.h"
#include "planner/plannodes/order_by_plan_node.h"
#include "planner/plannodes/seq_scan_plan_node.h"

namespace terrier::tpch {

Workload::Workload(common::ManagedPointer<DBMain> db_main, const std::string &db_name, const std::string &table_root) {
  // cache db main and members
  db_main_ = db_main;
  txn_manager_ = db_main_->GetTransactionLayer()->GetTransactionManager();
  block_store_ = db_main_->GetStorageLayer()->GetBlockStore();
  catalog_ = db_main_->GetCatalogLayer()->GetCatalog();
  txn_manager_ = db_main_->GetTransactionLayer()->GetTransactionManager();

  auto txn = txn_manager_->BeginTransaction();

  // Create database catalog and namespace
  db_oid_ = catalog_->CreateDatabase(common::ManagedPointer<transaction::TransactionContext>(txn), db_name, true);
  accessor_ =
      catalog_->GetAccessor(common::ManagedPointer<transaction::TransactionContext>(txn), db_oid_, DISABLED);
  ns_oid_ = accessor_->GetDefaultNamespace();

  // Make the execution context
  auto exec_ctx = execution::exec::ExecutionContext(
      db_oid_, common::ManagedPointer<transaction::TransactionContext>(txn), nullptr, nullptr,
      common::ManagedPointer<catalog::CatalogAccessor>(accessor_), exec_settings_);

  // create the TPCH database and compile the queries
  GenerateTPCHTables(&exec_ctx, table_root);
   LoadTPCHQueries();


  txn_manager_->Commit(txn, transaction::TransactionUtil::EmptyCallback, nullptr);
}

void Workload::GenerateTPCHTables(execution::exec::ExecutionContext *exec_ctx, const std::string &dir_name) {
  // TPCH table names;
  static const std::vector<std::string> tpch_tables{
      "part", "supplier", "partsupp", "customer", "orders", "lineitem", "nation", "region",
  };
  execution::sql::TableReader table_reader(exec_ctx, block_store_.Get(), ns_oid_);
  for (const auto &table_name : tpch_tables) {
    auto num_rows = table_reader.ReadTable(dir_name + table_name + ".schema", dir_name + table_name + ".data");
    EXECUTION_LOG_INFO("Wrote {} rows on table {}.", num_rows, table_name);
  }

}

void Workload::LoadTPCHQueries() {
  MakeExecutableQ1();
  queries_.emplace_back(std::move(q1_));
}


void Workload::Execute(int8_t worker_id, uint64_t execution_us_per_worker, uint64_t avg_interval_us, uint32_t query_num,
                       execution::vm::ExecutionMode mode) {
  // Shuffle the queries randomly for each thread
  auto total_query_num = queries_.size();
  std::vector<uint32_t> index;
  index.resize(total_query_num);
  for (uint32_t i = 0; i < total_query_num; ++i) index[i] = i;
  std::shuffle(index.begin(), index.end(), std::mt19937(time(nullptr) + worker_id));

  // Get the sleep time range distribution
  std::mt19937 generator{};
  std::uniform_int_distribution<uint64_t> distribution(avg_interval_us - avg_interval_us / 2,
                                                       avg_interval_us + avg_interval_us / 2);

  // Register to the metrics manager
  db_main_->GetMetricsManager()->RegisterThread();
  uint32_t counter = 0;
  uint64_t end_time = metrics::MetricsUtil::Now() + execution_us_per_worker;
  while (metrics::MetricsUtil::Now() < end_time) {
    // Executing all the queries on by one in round robin
    auto txn = txn_manager_->BeginTransaction();
    auto accessor =
        catalog_->GetAccessor(common::ManagedPointer<transaction::TransactionContext>(txn), db_oid_, DISABLED);

    auto output_schema = queries_[index[counter]]->GetPlan().GetOutputSchema().Get();
    execution::exec::OutputPrinter printer(output_schema);
    // execution::exec::OutputPrinter printer(output_schema);
    auto exec_ctx = execution::exec::ExecutionContext(
        db_oid_, common::ManagedPointer<transaction::TransactionContext>(txn), printer, output_schema,
        common::ManagedPointer<catalog::CatalogAccessor>(accessor_), exec_settings_);

    queries_[index[counter]]->Run(common::ManagedPointer<execution::exec::ExecutionContext>(&exec_ctx), mode);

    // Only execute up to query_num number of queries for this thread in round-robin
    counter = counter == query_num - 1 ? 0 : counter + 1;
    txn_manager_->Commit(txn, transaction::TransactionUtil::EmptyCallback, nullptr);

    // Sleep to create different execution frequency patterns
    auto random_sleep_time = distribution(generator);
    std::this_thread::sleep_for(std::chrono::microseconds(random_sleep_time));
  }

  // Unregister from the metrics manager
  db_main_->GetMetricsManager()->UnregisterThread();
}


void Workload::MakeExecutableQ1() {
  execution::compiler::test::ExpressionMaker expr_maker;
  auto table_oid = accessor_->GetTableOid("lineitem");
  const auto &l_schema = accessor_->GetSchema(table_oid);
  // Scan the table
  std::unique_ptr<planner::AbstractPlanNode> l_seq_scan;
  execution::compiler::test::OutputSchemaHelper l_seq_scan_out{0, &expr_maker};
  {
    // Read all needed columns
    auto l_returnflag = expr_maker.CVE(l_schema.GetColumn("l_returnflag").Oid(), type::TypeId::VARCHAR);
    auto l_linestatus = expr_maker.CVE(l_schema.GetColumn("l_linestatus").Oid(), type::TypeId::VARCHAR);
    auto l_extendedprice = expr_maker.CVE(l_schema.GetColumn("l_extendedprice").Oid(), type::TypeId::DECIMAL);
    auto l_discount = expr_maker.CVE(l_schema.GetColumn("l_discount").Oid(), type::TypeId::DECIMAL);
    auto l_tax = expr_maker.CVE(l_schema.GetColumn("l_tax").Oid(), type::TypeId::DECIMAL);
    auto l_quantity = expr_maker.CVE(l_schema.GetColumn("l_quantity").Oid(), type::TypeId::DECIMAL);
    auto l_shipdate = expr_maker.CVE(l_schema.GetColumn("l_shipdate").Oid(), type::TypeId::DATE);
    std::vector<catalog::col_oid_t> col_oids = {
        l_schema.GetColumn("l_returnflag").Oid(),    l_schema.GetColumn("l_linestatus").Oid(),
        l_schema.GetColumn("l_extendedprice").Oid(), l_schema.GetColumn("l_discount").Oid(),
        l_schema.GetColumn("l_tax").Oid(),           l_schema.GetColumn("l_quantity").Oid(),
        l_schema.GetColumn("l_shipdate").Oid()};
    // Make the output schema
    l_seq_scan_out.AddOutput("l_returnflag", l_returnflag);
    l_seq_scan_out.AddOutput("l_linestatus", l_linestatus);
    l_seq_scan_out.AddOutput("l_extendedprice", l_extendedprice);
    l_seq_scan_out.AddOutput("l_discount", l_discount);
    l_seq_scan_out.AddOutput("l_tax", l_tax);
    l_seq_scan_out.AddOutput("l_quantity", l_quantity);
    auto schema = l_seq_scan_out.MakeSchema();
    // Make the predicate
    l_seq_scan_out.AddOutput("l_shipdate", l_shipdate);
    auto date_const = expr_maker.Constant(1998, 9, 2);
    auto predicate = expr_maker.ComparisonLt(l_shipdate, date_const);
    // Build
    planner::SeqScanPlanNode::Builder builder;
    l_seq_scan = builder.SetOutputSchema(std::move(schema))
        .SetScanPredicate(predicate)
        .SetTableOid(table_oid)
        .SetColumnOids(std::move(col_oids))
        .Build();
  }
  // Make the aggregate
  std::unique_ptr<planner::AbstractPlanNode> agg;
  execution::compiler::test::OutputSchemaHelper agg_out{0, &expr_maker};
  {
    // Read previous layer's output
    auto l_returnflag = l_seq_scan_out.GetOutput("l_returnflag");
    auto l_linestatus = l_seq_scan_out.GetOutput("l_linestatus");
    auto l_quantity = l_seq_scan_out.GetOutput("l_quantity");
    auto l_extendedprice = l_seq_scan_out.GetOutput("l_extendedprice");
    auto l_discount = l_seq_scan_out.GetOutput("l_discount");
    auto l_tax = l_seq_scan_out.GetOutput("l_tax");
    // Make the aggregate expressions
    auto sum_qty = expr_maker.AggSum(l_quantity);
    auto sum_base_price = expr_maker.AggSum(l_extendedprice);
    auto one_const = expr_maker.Constant(1.0f);
    auto disc_price = expr_maker.OpMul(l_extendedprice, expr_maker.OpMin(one_const, l_discount));
    auto sum_disc_price = expr_maker.AggSum(disc_price);
    auto charge = expr_maker.OpMul(disc_price, expr_maker.OpSum(one_const, l_tax));
    auto sum_charge = expr_maker.AggSum(charge);
    auto avg_qty = expr_maker.AggAvg(l_quantity);
    auto avg_price = expr_maker.AggAvg(l_extendedprice);
    auto avg_disc = expr_maker.AggAvg(l_discount);
    auto count_order = expr_maker.AggCount(expr_maker.Constant(1));  // Works as Count(*)
    // Add them to the helper.
    agg_out.AddGroupByTerm("l_returnflag", l_returnflag);
    agg_out.AddGroupByTerm("l_linestatus", l_linestatus);
    agg_out.AddAggTerm("sum_qty", sum_qty);
    agg_out.AddAggTerm("sum_base_price", sum_base_price);
    agg_out.AddAggTerm("sum_disc_price", sum_disc_price);
    agg_out.AddAggTerm("sum_charge", sum_charge);
    agg_out.AddAggTerm("avg_qty", avg_qty);
    agg_out.AddAggTerm("avg_price", avg_price);
    agg_out.AddAggTerm("avg_disc", avg_disc);
    agg_out.AddAggTerm("count_order", count_order);
    // Make the output schema
    agg_out.AddOutput("l_returnflag", agg_out.GetGroupByTermForOutput("l_returnflag"));
    agg_out.AddOutput("l_linestatus", agg_out.GetGroupByTermForOutput("l_linestatus"));
    agg_out.AddOutput("sum_qty", agg_out.GetAggTermForOutput("sum_qty"));
    agg_out.AddOutput("sum_base_price", agg_out.GetAggTermForOutput("sum_base_price"));
    agg_out.AddOutput("sum_disc_price", agg_out.GetAggTermForOutput("sum_disc_price"));
    agg_out.AddOutput("sum_charge", agg_out.GetAggTermForOutput("sum_charge"));
    agg_out.AddOutput("avg_qty", agg_out.GetAggTermForOutput("avg_qty"));
    agg_out.AddOutput("avg_price", agg_out.GetAggTermForOutput("avg_price"));
    agg_out.AddOutput("avg_disc", agg_out.GetAggTermForOutput("avg_disc"));
    agg_out.AddOutput("count_order", agg_out.GetAggTermForOutput("count_order"));
    auto schema = agg_out.MakeSchema();
    // Build
    planner::AggregatePlanNode::Builder builder;
    agg = builder.SetOutputSchema(std::move(schema))
        .AddGroupByTerm(l_returnflag)
        .AddGroupByTerm(l_linestatus)
        .AddAggregateTerm(sum_qty)
        .AddAggregateTerm(sum_base_price)
        .AddAggregateTerm(sum_disc_price)
        .AddAggregateTerm(sum_charge)
        .AddAggregateTerm(avg_qty)
        .AddAggregateTerm(avg_price)
        .AddAggregateTerm(avg_disc)
        .AddAggregateTerm(count_order)
        .AddChild(std::move(l_seq_scan))
        .SetAggregateStrategyType(planner::AggregateStrategyType::HASH)
        .SetHavingClausePredicate(nullptr)
        .Build();
  }

  // Order By
  std::unique_ptr<planner::AbstractPlanNode> order_by;
  execution::compiler::test::OutputSchemaHelper order_by_out{0, &expr_maker};
  {
    // Output Colums col1, col2, col1 + col2
    auto l_returnflag = agg_out.GetOutput("l_returnflag");
    auto l_linestatus = agg_out.GetOutput("l_linestatus");
    auto sum_qty = agg_out.GetOutput("sum_qty");
    auto sum_base_price = agg_out.GetOutput("sum_base_price");
    auto sum_disc_price = agg_out.GetOutput("sum_disc_price");
    auto sum_charge = agg_out.GetOutput("sum_charge");
    auto avg_qty = agg_out.GetOutput("avg_qty");
    auto avg_price = agg_out.GetOutput("avg_price");
    auto avg_disc = agg_out.GetOutput("avg_disc");
    auto count_order = agg_out.GetOutput("count_order");
    order_by_out.AddOutput("l_returnflag", l_returnflag);
    order_by_out.AddOutput("l_linestatus", l_linestatus);
    order_by_out.AddOutput("sum_qty", sum_qty);
    order_by_out.AddOutput("sum_base_price", sum_base_price);
    order_by_out.AddOutput("sum_disc_price", sum_disc_price);
    order_by_out.AddOutput("sum_charge", sum_charge);
    order_by_out.AddOutput("avg_qty", avg_qty);
    order_by_out.AddOutput("avg_price", avg_price);
    order_by_out.AddOutput("avg_disc", avg_disc);
    order_by_out.AddOutput("count_order", count_order);
    auto schema = order_by_out.MakeSchema();
    // Order By Clause
    planner::SortKey clause1{l_returnflag, optimizer::OrderByOrderingType::ASC};
    planner::SortKey clause2{l_linestatus, optimizer::OrderByOrderingType::ASC};
    // Build
    planner::OrderByPlanNode::Builder builder;
    order_by = builder.SetOutputSchema(std::move(schema))
        .AddChild(std::move(agg))
        .AddSortKey(clause1.first, clause1.second)
        .AddSortKey(clause2.first, clause2.second)
        .Build();
  }
  auto last_op = order_by.get();
  auto exec_query = execution::compiler::CompilationContext::Compile(*last_op, exec_settings_, accessor_.get());
  q1_ = std::move(exec_query);

}
}  // namespace terrier::tpch
