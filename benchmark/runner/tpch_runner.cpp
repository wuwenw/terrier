

#include <loggers/execution_logger.h>

#include "benchmark/benchmark.h"
#include "common/scoped_timer.h"
#include "common/worker_pool.h"
#include "execution/compiler/compilation_context.h"
#include "execution/compiler/expression_maker.h"
#include "execution/compiler/output_schema_util.h"
#include "execution/exec/execution_context.h"
#include "execution/execution_util.h"
#include "execution/sql/sql.h"
#include "execution/vm/module.h"
#include "main/db_main.h"
#include "planner/plannodes/aggregate_plan_node.h"
#include "planner/plannodes/order_by_plan_node.h"
#include "planner/plannodes/seq_scan_plan_node.h"
#include "storage/sql_table.h"
#include "test_util/tpch/workload.h"
namespace terrier::runner {
class TPCHRunner : public benchmark::Fixture {
 public:
  const int8_t total_num_threads_ = 4;                // defines the number of terminals (workers threads)
  const uint64_t execution_us_per_worker_ = 1000000;  // Time (us) to run per terminal (worker thread)
  std::vector<uint64_t> avg_interval_us_ = {10, 20, 50, 100, 200, 500, 1000};
  const execution::vm::ExecutionMode mode_ = execution::vm::ExecutionMode::Interpret;

  std::unique_ptr<DBMain> db_main_;
  std::unique_ptr<tpch::Workload> tpch_workload_;
  common::ManagedPointer<transaction::TransactionManager> txn_manager_;
  transaction::TransactionContext *txn_;
  catalog::db_oid_t db_oid_;
  std::unique_ptr<catalog::CatalogAccessor> accessor_;
  execution::exec::ExecutionSettings exec_settings_{};

  const std::string tpch_table_root_ = "../../../tpl_tables/tables/";
  const std::string tpch_database_name_ = "tpch_db";

  void SetUp(const benchmark::State &state) final {
    terrier::execution::ExecutionUtil::InitTPL();
    auto db_main_builder = DBMain::Builder()
                               .SetUseGC(true)
                               .SetUseCatalog(true)
                               .SetUseGCThread(true)
                               .SetUseMetrics(true)
                               .SetUseMetricsThread(true)
                               .SetBlockStoreSize(1000000)
                               .SetBlockStoreReuse(1000000)
                               .SetRecordBufferSegmentSize(1000000)
                               .SetRecordBufferSegmentReuse(1000000);
    db_main_ = db_main_builder.Build();
    txn_manager_ = db_main_->GetTransactionLayer()->GetTransactionManager();
    txn_ = txn_manager_->BeginTransaction();
    db_oid_ = db_main_->GetCatalogLayer()->GetCatalog()->CreateDatabase(
        common::ManagedPointer<transaction::TransactionContext>(txn_), tpch_database_name_, true);
    accessor_ = db_main_->GetCatalogLayer()->GetCatalog()->GetAccessor(
        common::ManagedPointer<transaction::TransactionContext>(txn_), db_oid_, DISABLED);

    // Make the execution context
    auto exec_ctx = execution::exec::ExecutionContext(
        db_oid_, common::ManagedPointer<transaction::TransactionContext>(txn_), nullptr, nullptr,
        common::ManagedPointer<catalog::CatalogAccessor>(accessor_), exec_settings_);

    auto metrics_manager = db_main_->GetMetricsManager();
    metrics_manager->EnableMetric(metrics::MetricsComponent::EXECUTION, 0);
    metrics_manager->EnableMetric(metrics::MetricsComponent::GARBAGECOLLECTION, 0);
    metrics_manager->EnableMetric(metrics::MetricsComponent::LOGGING, 0);

    tpch_workload_ = std::make_unique<tpch::Workload>(common::ManagedPointer<DBMain>(db_main_), tpch_database_name_,
                                                      tpch_table_root_, txn_, &exec_ctx);
  }

  void TearDown(const benchmark::State &state) final {
    terrier::execution::ExecutionUtil::ShutdownTPL();
    // free db main here so we don't need to use the loggers anymore
    db_main_.reset();
  }
};

BENCHMARK_DEFINE_F(TPCHRunner, Q1)(benchmark::State &state) {
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
    std::vector<catalog::col_oid_t> col_oids = {
        l_schema.GetColumn("l_returnflag").Oid(),    l_schema.GetColumn("l_linestatus").Oid(),
        l_schema.GetColumn("l_extendedprice").Oid(), l_schema.GetColumn("l_discount").Oid(),
        l_schema.GetColumn("l_tax").Oid(),           l_schema.GetColumn("l_quantity").Oid(),
        l_schema.GetColumn("l_shipdate").Oid()};
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

  // Compile plan
  auto last_op = order_by.get();
  execution::exec::OutputPrinter printer(last_op->GetOutputSchema().Get());

  auto exec_ctx = execution::exec::ExecutionContext(
      db_oid_, common::ManagedPointer<transaction::TransactionContext>(txn_), printer, last_op->GetOutputSchema().Get(),
      common::ManagedPointer<catalog::CatalogAccessor>(accessor_), exec_settings_);

  auto query = execution::compiler::CompilationContext::Compile(*last_op, exec_settings_, accessor_.get());
  // Run Once to force compilation
  query->Run(common::ManagedPointer(&exec_ctx), execution::vm::ExecutionMode::Interpret);
  // Only time execution
  for (auto _ : state) {
    query->Run(common::ManagedPointer(&exec_ctx), execution::vm::ExecutionMode::Interpret);
  }
}

BENCHMARK_REGISTER_F(TPCHRunner, Q1)->Unit(benchmark::kMillisecond)->UseManualTime()->Iterations(10);

}  // namespace terrier::runner
