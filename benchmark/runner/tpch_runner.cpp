

#include "loggers/execution_logger.h"

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
#include "planner/plannodes/hash_join_plan_node.h"
#include "planner/plannodes/nested_loop_join_plan_node.h"
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

BENCHMARK_DEFINE_F(TPCHRunner, Q16)(benchmark::State &state) {
  execution::compiler::test::ExpressionMaker expr_maker;
  // Part.
  auto p_table_oid = accessor_->GetTableOid("part");
  const auto &p_schema = accessor_->GetSchema(p_table_oid);
  // Partsupp.
//  auto ps_table_oid = accessor_->GetTableOid("partsupp");
//  const auto &ps_schema = accessor_->GetSchema(ps_table_oid);
//  // Supplier.
//  auto s_table_oid = accessor_->GetTableOid("supplier");
//  const auto &s_schema = accessor_->GetSchema(s_table_oid);
  // Scan part
  std::unique_ptr<planner::AbstractPlanNode> p_seq_scan;
  execution::compiler::test::OutputSchemaHelper p_seq_scan_out{0, &expr_maker};
  {
    // Read all needed columns
    auto p_brand = expr_maker.CVE(p_schema.GetColumn("p_brand").Oid(), type::TypeId::VARCHAR);
    auto p_type = expr_maker.CVE(p_schema.GetColumn("p_type").Oid(), type::TypeId::VARCHAR);
    auto p_partkey = expr_maker.CVE(p_schema.GetColumn("p_partkey").Oid(), type::TypeId::INTEGER);
    auto p_size = expr_maker.CVE(p_schema.GetColumn("p_size").Oid(), type::TypeId::INTEGER);
    std::vector<catalog::col_oid_t> p_col_oids = {
        p_schema.GetColumn("p_brand").Oid(), p_schema.GetColumn("p_type").Oid(), p_schema.GetColumn("p_partkey").Oid(),
        p_schema.GetColumn("p_size").Oid()};
    // Make the output schema
    p_seq_scan_out.AddOutput("p_brand", p_brand);
    p_seq_scan_out.AddOutput("p_type", p_type);
    p_seq_scan_out.AddOutput("p_partkey", p_partkey);
    p_seq_scan_out.AddOutput("p_size", p_size);
    auto schema = p_seq_scan_out.MakeSchema();

    // Predicate
    auto brand_comp = expr_maker.ComparisonNeq(p_brand, expr_maker.Constant("Brand#45"));
    auto type_like = expr_maker.Constant("MEDIUM POLISHED%");
    auto like_call =
        expr_maker.Function("like", {p_type, type_like}, type::TypeId::BOOLEAN, catalog::postgres::LIKE_PRO_OID);
    auto conversion_call =
        expr_maker.Function("sqlToBool", {like_call}, type::TypeId::BOOLEAN, catalog::postgres::SQL_TO_BOOL_PRO_OID);
    auto type_comp = expr_maker.OpNot(conversion_call);
    auto size_comp = expr_maker.ConjunctionOr(
        expr_maker.ComparisonEq(p_size, expr_maker.Constant(49)),
        expr_maker.ConjunctionOr(
            expr_maker.ComparisonEq(p_size, expr_maker.Constant(14)),
            expr_maker.ConjunctionOr(
                expr_maker.ComparisonEq(p_size, expr_maker.Constant(23)),
                expr_maker.ConjunctionOr(
                    expr_maker.ComparisonEq(p_size, expr_maker.Constant(45)),
                    expr_maker.ConjunctionOr(
                        expr_maker.ComparisonEq(p_size, expr_maker.Constant(19)),
                        expr_maker.ConjunctionOr(
                            expr_maker.ComparisonEq(p_size, expr_maker.Constant(3)),
                            expr_maker.ConjunctionOr(expr_maker.ComparisonEq(p_size, expr_maker.Constant(36)),
                                                     expr_maker.ComparisonEq(p_size, expr_maker.Constant(9)))))))));
    auto predicate = expr_maker.ConjunctionAnd(brand_comp, expr_maker.ConjunctionAnd(type_comp, size_comp));
    // Build
    planner::SeqScanPlanNode::Builder builder;
    p_seq_scan = builder.SetOutputSchema(std::move(schema))
                     .SetScanPredicate(predicate)
                     .SetTableOid(p_table_oid)
                     .SetColumnOids(std::move(p_col_oids))
                     .Build();
  }

//  // Scan supplier
//  std::unique_ptr<planner::AbstractPlanNode> s_seq_scan;
//  execution::compiler::test::OutputSchemaHelper s_seq_scan_out{0, &expr_maker};
//  {
//    // Read all needed columns
//    auto s_suppkey = expr_maker.CVE(s_schema.GetColumn("s_suppkey").Oid(), type::TypeId::INTEGER);
//    auto s_comment = expr_maker.CVE(s_schema.GetColumn("s_comment").Oid(), type::TypeId::VARCHAR);
//    std::vector<catalog::col_oid_t> s_col_oids = {s_schema.GetColumn("s_suppkey").Oid(),
//                                                  s_schema.GetColumn("s_comment").Oid()};
//    // Make the output schema
//    s_seq_scan_out.AddOutput("s_suppkey", s_suppkey);
//    auto schema = s_seq_scan_out.MakeSchema();
//    // Predicate
//    auto comment_like = expr_maker.Constant("%Customer%Complaints%");
//    auto like_call =
//        expr_maker.Function("like", {s_comment, comment_like}, type::TypeId::BOOLEAN, catalog::postgres::LIKE_PRO_OID);
//    // auto predicate = expr_maker.Function("sqlToBool", {like_call}, type::TypeId::BOOLEAN, catalog::postgres::SQL_TO_BOOL_PRO_OID);
//    // Build
//    planner::SeqScanPlanNode::Builder builder;
//    s_seq_scan = builder.SetOutputSchema(std::move(schema))
//                     .SetScanPredicate(like_call)
//                     .SetTableOid(s_table_oid)
//                     .SetColumnOids(std::move(s_col_oids))
//                     .Build();
//  }
//
//  // Scan partsupp
//  std::unique_ptr<planner::AbstractPlanNode> ps_seq_scan;
//  execution::compiler::test::OutputSchemaHelper ps_seq_scan_out{1, &expr_maker};
//  {
//    // Read all needed columns
//    auto ps_suppkey = expr_maker.CVE(ps_schema.GetColumn("ps_suppkey").Oid(), type::TypeId::INTEGER);
//    auto ps_partkey = expr_maker.CVE(ps_schema.GetColumn("ps_partkey").Oid(), type::TypeId::INTEGER);
//    std::vector<catalog::col_oid_t> ps_col_oids = {ps_schema.GetColumn("ps_suppkey").Oid(),
//                                                   ps_schema.GetColumn("ps_partkey").Oid()};
//    // Make the output schema
//    ps_seq_scan_out.AddOutput("ps_suppkey", ps_suppkey);
//    ps_seq_scan_out.AddOutput("ps_partkey", ps_partkey);
//    auto schema = ps_seq_scan_out.MakeSchema();
//    // Build
//    planner::SeqScanPlanNode::Builder builder;
//    ps_seq_scan = builder.SetOutputSchema(std::move(schema))
//                      .SetScanPredicate(nullptr)
//                      .SetTableOid(ps_table_oid)
//                      .SetColumnOids(std::move(ps_col_oids))
//                      .Build();
//  }
//
//  // First hash join
//  // Hash Join 1
//  std::unique_ptr<planner::AbstractPlanNode> hash_join1;
//  execution::compiler::test::OutputSchemaHelper hash_join_out1{1, &expr_maker};
//  {
//    // Left columns
//    auto p_brand = p_seq_scan_out.GetOutput("p_brand");
//    auto p_type = p_seq_scan_out.GetOutput("p_type");
//    auto p_size = p_seq_scan_out.GetOutput("p_size");
//    auto p_partkey = p_seq_scan_out.GetOutput("p_partkey");
//    // Right columns
//    auto ps_suppkey = ps_seq_scan_out.GetOutput("ps_suppkey");
//    auto ps_partkey = ps_seq_scan_out.GetOutput("ps_partkey");
//    // Output Schema
//    hash_join_out1.AddOutput("p_brand", p_brand);
//    hash_join_out1.AddOutput("p_type", p_type);
//    hash_join_out1.AddOutput("p_size", p_size);
//    hash_join_out1.AddOutput("ps_suppkey", ps_suppkey);
//    auto schema = hash_join_out1.MakeSchema();
//    // Predicate
//    auto predicate = expr_maker.ComparisonEq(p_partkey, ps_partkey);
//    // Build
//    planner::HashJoinPlanNode::Builder builder;
//    hash_join1 = builder.AddChild(std::move(p_seq_scan))
//                     .AddChild(std::move(ps_seq_scan))
//                     .SetOutputSchema(std::move(schema))
//                     .AddLeftHashKey(p_partkey)
//                     .AddRightHashKey(ps_partkey)
//                     .SetJoinType(planner::LogicalJoinType::INNER)
//                     .SetJoinPredicate(predicate)
//                     .Build();
//  }
//
//  // Second hash join
//  std::unique_ptr<planner::AbstractPlanNode> hash_join2;
//  execution::compiler::test::OutputSchemaHelper hash_join_out2{0, &expr_maker};
//  {
//    // Left columns
//    auto s_suppkey = s_seq_scan_out.GetOutput("s_suppkey");
//    // Right columns
//    auto p_brand = hash_join_out1.GetOutput("p_brand");
//    auto p_type = hash_join_out1.GetOutput("p_type");
//    auto p_size = hash_join_out1.GetOutput("p_size");
//    auto ps_suppkey = hash_join_out1.GetOutput("ps_suppkey");
//    // Output Schema
//    hash_join_out2.AddOutput("p_brand", p_brand);
//    hash_join_out2.AddOutput("p_type", p_type);
//    hash_join_out2.AddOutput("p_size", p_size);
//    hash_join_out2.AddOutput("ps_suppkey", ps_suppkey);
//    auto schema = hash_join_out2.MakeSchema();
//    // Predicate
//    auto predicate = expr_maker.ComparisonEq(s_suppkey, ps_suppkey);
//    // Build
//    planner::HashJoinPlanNode::Builder builder;
//    hash_join2 = builder.AddChild(std::move(s_seq_scan))
//                     .AddChild(std::move(hash_join1))
//                     .SetOutputSchema(std::move(schema))
//                     .AddLeftHashKey(s_suppkey)
//                     .AddRightHashKey(ps_suppkey)
//                     .SetJoinType(planner::LogicalJoinType::RIGHT_ANTI)
//                     .SetJoinPredicate(predicate)
//                     .Build();
//  }
//
//  // Make the aggregate
//  std::unique_ptr<planner::AbstractPlanNode> agg;
//  execution::compiler::test::OutputSchemaHelper agg_out{0, &expr_maker};
//  {
//    // Read previous layer's output
//    auto p_brand = hash_join_out2.GetOutput("p_brand");
//    auto p_type = hash_join_out2.GetOutput("p_type");
//    auto p_size = hash_join_out2.GetOutput("p_size");
//    auto ps_suppkey = hash_join_out2.GetOutput("ps_suppkey");
//    // Make the aggregate expressions
//    auto supplier_cnt = expr_maker.AggCount(ps_suppkey, true);
//    // Add them to the helper.
//    agg_out.AddGroupByTerm("p_brand", p_brand);
//    agg_out.AddGroupByTerm("p_type", p_type);
//    agg_out.AddGroupByTerm("p_size", p_size);
//    agg_out.AddAggTerm("supplier_cnt", supplier_cnt);
//    // Make the output schema
//    agg_out.AddOutput("p_brand", agg_out.GetGroupByTermForOutput("p_brand"));
//    agg_out.AddOutput("p_type", agg_out.GetGroupByTermForOutput("p_type"));
//    agg_out.AddOutput("p_size", agg_out.GetGroupByTermForOutput("p_size"));
//    agg_out.AddOutput("supplier_cnt", agg_out.GetAggTermForOutput("supplier_cnt"));
//    auto schema = agg_out.MakeSchema();
//    // Build
//    planner::AggregatePlanNode::Builder builder;
//    agg = builder.SetOutputSchema(std::move(schema))
//              .AddGroupByTerm(p_brand)
//              .AddGroupByTerm(p_type)
//              .AddGroupByTerm(p_size)
//              .AddAggregateTerm(supplier_cnt)
//              .AddChild(std::move(hash_join2))
//              .SetAggregateStrategyType(planner::AggregateStrategyType::HASH)
//              .SetHavingClausePredicate(nullptr)
//              .Build();
//  }
//
//  // Order By
//  std::unique_ptr<planner::AbstractPlanNode> order_by;
//  execution::compiler::test::OutputSchemaHelper order_by_out{0, &expr_maker};
//  {
//    // Read previous layer
//    auto p_brand = agg_out.GetOutput("p_brand");
//    auto p_type = agg_out.GetOutput("p_type");
//    auto p_size = agg_out.GetOutput("p_size");
//    auto supplier_cnt = agg_out.GetOutput("supplier_cnt");
//
//    order_by_out.AddOutput("p_brand", p_brand);
//    order_by_out.AddOutput("p_type", p_type);
//    order_by_out.AddOutput("p_size", p_size);
//    order_by_out.AddOutput("supplier_cnt", supplier_cnt);
//    auto schema = order_by_out.MakeSchema();
//    // Order By Clause
//    planner::SortKey clause1{supplier_cnt, optimizer::OrderByOrderingType::DESC};
//    planner::SortKey clause2{p_brand, optimizer::OrderByOrderingType::ASC};
//    planner::SortKey clause3{p_type, optimizer::OrderByOrderingType::ASC};
//    planner::SortKey clause4{p_size, optimizer::OrderByOrderingType::ASC};
//    // Build
//    planner::OrderByPlanNode::Builder builder;
//    order_by = builder.SetOutputSchema(std::move(schema))
//                   .AddChild(std::move(agg))
//                   .AddSortKey(clause1.first, clause1.second)
//                   .AddSortKey(clause2.first, clause2.second)
//                   .AddSortKey(clause3.first, clause3.second)
//                   .AddSortKey(clause4.first, clause4.second)
//                   .Build();
//  }

  // Compile plan
  auto last_op = p_seq_scan.get();
  execution::exec::OutputPrinter printer(last_op->GetOutputSchema().Get());
  txn_ = txn_manager_->BeginTransaction();
  auto exec_ctx_q6 = execution::exec::ExecutionContext(
      db_oid_, common::ManagedPointer<transaction::TransactionContext>(txn_), printer, last_op->GetOutputSchema().Get(),
      common::ManagedPointer<catalog::CatalogAccessor>(accessor_), exec_settings_);

  auto query = execution::compiler::CompilationContext::Compile(*last_op, exec_settings_, accessor_.get());
  // Run Once to force compilation
  query->Run(common::ManagedPointer(&exec_ctx_q6), execution::vm::ExecutionMode::Interpret);
  // Only time execution
  for (auto _ : state) {
    query->Run(common::ManagedPointer(&exec_ctx_q6), execution::vm::ExecutionMode::Interpret);
  }
  txn_manager_->Commit(txn_, transaction::TransactionUtil::EmptyCallback, nullptr);
}

BENCHMARK_DEFINE_F(TPCHRunner, Q18)(benchmark::State &state) {
  execution::compiler::test::ExpressionMaker expr_maker;
  // Customer.
  auto c_table_oid = accessor_->GetTableOid("customer");
  const auto &c_schema = accessor_->GetSchema(c_table_oid);
  // Orders.
  auto o_table_oid = accessor_->GetTableOid("orders");
  const auto &o_schema = accessor_->GetSchema(o_table_oid);
  // Lineitem.
  auto l_table_oid = accessor_->GetTableOid("lineitem");
  const auto &l_schema = accessor_->GetSchema(l_table_oid);
  // Scan customer
  std::unique_ptr<planner::AbstractPlanNode> c_seq_scan;
  execution::compiler::test::OutputSchemaHelper c_seq_scan_out{0, &expr_maker};
  {
    // Read all needed columns
    auto c_custkey = expr_maker.CVE(c_schema.GetColumn("c_custkey").Oid(), type::TypeId::INTEGER);
    auto c_name = expr_maker.CVE(c_schema.GetColumn("c_name").Oid(), type::TypeId::VARCHAR);
    std::vector<catalog::col_oid_t> c_col_oids = {c_schema.GetColumn("c_custkey").Oid(),
                                                  c_schema.GetColumn("c_name").Oid()};
    // Make the output schema
    c_seq_scan_out.AddOutput("c_custkey", c_custkey);
    c_seq_scan_out.AddOutput("c_name", c_name);
    auto schema = c_seq_scan_out.MakeSchema();
    // Build
    planner::SeqScanPlanNode::Builder builder;
    c_seq_scan = builder.SetOutputSchema(std::move(schema))
                     .SetScanPredicate(nullptr)
                     .SetTableOid(c_table_oid)
                     .SetColumnOids(std::move(c_col_oids))
                     .Build();
  }
  // Scan orders
  std::unique_ptr<planner::AbstractPlanNode> o_seq_scan;
  execution::compiler::test::OutputSchemaHelper o_seq_scan_out{1, &expr_maker};
  {
    // Read all needed columns
    auto o_orderkey = expr_maker.CVE(o_schema.GetColumn("o_orderkey").Oid(), type::TypeId::INTEGER);
    auto o_custkey = expr_maker.CVE(o_schema.GetColumn("o_custkey").Oid(), type::TypeId::INTEGER);
    auto o_orderdate = expr_maker.CVE(o_schema.GetColumn("o_orderdate").Oid(), type::TypeId::DATE);
    auto o_totalprice = expr_maker.CVE(o_schema.GetColumn("o_totalprice").Oid(), type::TypeId::DECIMAL);
    std::vector<catalog::col_oid_t> o_col_oids = {
        o_schema.GetColumn("o_orderkey").Oid(), o_schema.GetColumn("o_custkey").Oid(),
        o_schema.GetColumn("o_orderdate").Oid(), o_schema.GetColumn("o_totalprice").Oid()};
    // Make the output schema
    o_seq_scan_out.AddOutput("o_orderkey", o_orderkey);
    o_seq_scan_out.AddOutput("o_custkey", o_custkey);
    o_seq_scan_out.AddOutput("o_orderdate", o_orderdate);
    o_seq_scan_out.AddOutput("o_totalprice", o_totalprice);
    auto schema = o_seq_scan_out.MakeSchema();
    // Build
    planner::SeqScanPlanNode::Builder builder;
    o_seq_scan = builder.SetOutputSchema(std::move(schema))
                     .SetScanPredicate(nullptr)
                     .SetTableOid(o_table_oid)
                     .SetColumnOids(std::move(o_col_oids))
                     .Build();
  }
  // Scan lineitem1
  std::unique_ptr<planner::AbstractPlanNode> l_seq_scan1;
  execution::compiler::test::OutputSchemaHelper l_seq_scan_out1{0, &expr_maker};
  {
    // Read all needed columns
    auto l_quantity = expr_maker.CVE(l_schema.GetColumn("l_quantity").Oid(), type::TypeId::DECIMAL);
    auto l_orderkey = expr_maker.CVE(l_schema.GetColumn("l_orderkey").Oid(), type::TypeId::INTEGER);
    std::vector<catalog::col_oid_t> l_col_oids = {
        l_schema.GetColumn("l_quantity").Oid(),
        l_schema.GetColumn("l_orderkey").Oid(),
    };
    // Make the output schema
    l_seq_scan_out1.AddOutput("l_quantity", l_quantity);
    l_seq_scan_out1.AddOutput("l_orderkey", l_orderkey);
    auto schema = l_seq_scan_out1.MakeSchema();
    // Build
    planner::SeqScanPlanNode::Builder builder;
    l_seq_scan1 = builder.SetOutputSchema(std::move(schema))
                      .SetScanPredicate(nullptr)
                      .SetTableOid(l_table_oid)
                      .SetColumnOids(std::move(l_col_oids))
                      .Build();
  }
  // Scan lineitem2
  std::unique_ptr<planner::AbstractPlanNode> l_seq_scan2;
  execution::compiler::test::OutputSchemaHelper l_seq_scan_out2{1, &expr_maker};
  {
    // Read all needed columns
    auto l_quantity = expr_maker.CVE(l_schema.GetColumn("l_quantity").Oid(), type::TypeId::DECIMAL);
    auto l_orderkey = expr_maker.CVE(l_schema.GetColumn("l_orderkey").Oid(), type::TypeId::INTEGER);
    std::vector<catalog::col_oid_t> l2_col_oids = {
        l_schema.GetColumn("l_quantity").Oid(),
        l_schema.GetColumn("l_orderkey").Oid(),
    };
    // Make the output schema
    l_seq_scan_out2.AddOutput("l_quantity", l_quantity);
    l_seq_scan_out2.AddOutput("l_orderkey", l_orderkey);
    auto schema = l_seq_scan_out2.MakeSchema();
    // Build
    planner::SeqScanPlanNode::Builder builder;
    l_seq_scan2 = builder.SetOutputSchema(std::move(schema))
                      .SetScanPredicate(nullptr)
                      .SetTableOid(l_table_oid)
                      .SetColumnOids(std::move(l2_col_oids))
                      .Build();
  }
  // Make the aggregate
  std::unique_ptr<planner::AbstractPlanNode> agg1;
  execution::compiler::test::OutputSchemaHelper agg_out1{0, &expr_maker};
  {
    // Read previous layer's output
    auto l_orderkey = l_seq_scan_out1.GetOutput("l_orderkey");
    auto l_quantity = l_seq_scan_out1.GetOutput("l_quantity");
    // Make the aggregate expressions
    auto sum_qty = expr_maker.AggSum(l_quantity);
    // Add them to the helper.
    agg_out1.AddGroupByTerm("l_orderkey", l_orderkey);
    agg_out1.AddAggTerm("sum_qty", sum_qty);
    // Make the output schema
    agg_out1.AddOutput("l_orderkey", agg_out1.GetGroupByTermForOutput("l_orderkey"));
    auto schema = agg_out1.MakeSchema();
    // Make having
    auto having = expr_maker.ComparisonGt(agg_out1.GetAggTermForOutput("sum_qty"), expr_maker.Constant(300.0f));
    // Build
    planner::AggregatePlanNode::Builder builder;
    agg1 = builder.SetOutputSchema(std::move(schema))
               .AddGroupByTerm(l_orderkey)
               .AddAggregateTerm(sum_qty)
               .AddChild(std::move(l_seq_scan1))
               .SetAggregateStrategyType(planner::AggregateStrategyType::HASH)
               .SetHavingClausePredicate(having)
               .Build();
  }
  // First hash join
  // Hash Join 1
  std::unique_ptr<planner::AbstractPlanNode> hash_join1;
  execution::compiler::test::OutputSchemaHelper hash_join_out1{1, &expr_maker};
  {
    // Left columns
    auto l_orderkey = agg_out1.GetOutput("l_orderkey");
    // Right columns
    auto o_orderkey = o_seq_scan_out.GetOutput("o_orderkey");
    auto o_orderdate = o_seq_scan_out.GetOutput("o_orderdate");
    auto o_totalprice = o_seq_scan_out.GetOutput("o_totalprice");
    auto o_custkey = o_seq_scan_out.GetOutput("o_custkey");
    // Output Schema
    hash_join_out1.AddOutput("o_orderkey", o_orderkey);
    hash_join_out1.AddOutput("o_orderdate", o_orderdate);
    hash_join_out1.AddOutput("o_totalprice", o_totalprice);
    hash_join_out1.AddOutput("o_custkey", o_custkey);
    auto schema = hash_join_out1.MakeSchema();
    // Predicate
    auto predicate = expr_maker.ComparisonEq(l_orderkey, o_orderkey);
    // Build
    planner::HashJoinPlanNode::Builder builder;
    hash_join1 = builder.AddChild(std::move(agg1))
                     .AddChild(std::move(o_seq_scan))
                     .SetOutputSchema(std::move(schema))
                     .AddLeftHashKey(l_orderkey)
                     .AddRightHashKey(o_orderkey)
                     .SetJoinType(planner::LogicalJoinType::RIGHT_SEMI)
                     .SetJoinPredicate(predicate)
                     .Build();
  }
  // Second hash join
  std::unique_ptr<planner::AbstractPlanNode> hash_join2;
  execution::compiler::test::OutputSchemaHelper hash_join_out2{0, &expr_maker};
  {
    // Left columns
    auto c_custkey = c_seq_scan_out.GetOutput("c_custkey");
    auto c_name = c_seq_scan_out.GetOutput("c_name");
    // Right columns
    auto o_orderkey = hash_join_out1.GetOutput("o_orderkey");
    auto o_orderdate = hash_join_out1.GetOutput("o_orderdate");
    auto o_totalprice = hash_join_out1.GetOutput("o_totalprice");
    auto o_custkey = hash_join_out1.GetOutput("o_custkey");
    // Output Schema
    hash_join_out2.AddOutput("c_name", c_name);
    hash_join_out2.AddOutput("c_custkey", c_custkey);
    hash_join_out2.AddOutput("o_orderkey", o_orderkey);
    hash_join_out2.AddOutput("o_orderdate", o_orderdate);
    hash_join_out2.AddOutput("o_totalprice", o_totalprice);
    auto schema = hash_join_out2.MakeSchema();
    // Predicate
    auto predicate = expr_maker.ComparisonEq(c_custkey, o_custkey);
    // Build
    planner::HashJoinPlanNode::Builder builder;
    hash_join2 = builder.AddChild(std::move(c_seq_scan))
                     .AddChild(std::move(hash_join1))
                     .SetOutputSchema(std::move(schema))
                     .AddLeftHashKey(c_custkey)
                     .AddRightHashKey(o_custkey)
                     .SetJoinType(planner::LogicalJoinType::INNER)
                     .SetJoinPredicate(predicate)
                     .Build();
  }
  // Make third hash join
  std::unique_ptr<planner::AbstractPlanNode> hash_join3;
  execution::compiler::test::OutputSchemaHelper hash_join_out3{0, &expr_maker};
  {
    // Left columns
    auto c_name = hash_join_out2.GetOutput("c_name");
    auto c_custkey = hash_join_out2.GetOutput("c_custkey");
    auto o_orderkey = hash_join_out2.GetOutput("o_orderkey");
    auto o_orderdate = hash_join_out2.GetOutput("o_orderdate");
    auto o_totalprice = hash_join_out2.GetOutput("o_totalprice");
    // Right columns
    auto l_orderkey = l_seq_scan_out2.GetOutput("l_orderkey");
    auto l_quantity = l_seq_scan_out2.GetOutput("l_quantity");
    // Output Schema
    hash_join_out3.AddOutput("c_name", c_name);
    hash_join_out3.AddOutput("c_custkey", c_custkey);
    hash_join_out3.AddOutput("o_orderkey", o_orderkey);
    hash_join_out3.AddOutput("o_orderdate", o_orderdate);
    hash_join_out3.AddOutput("o_totalprice", o_totalprice);
    hash_join_out3.AddOutput("l_quantity", l_quantity);
    auto schema = hash_join_out3.MakeSchema();
    // Predicate
    auto predicate = expr_maker.ComparisonEq(o_orderkey, l_orderkey);
    // Build
    planner::HashJoinPlanNode::Builder builder;
    hash_join3 = builder.AddChild(std::move(hash_join2))
                     .AddChild(std::move(l_seq_scan2))
                     .SetOutputSchema(std::move(schema))
                     .AddLeftHashKey(o_orderkey)
                     .AddRightHashKey(l_orderkey)
                     .SetJoinType(planner::LogicalJoinType::INNER)
                     .SetJoinPredicate(predicate)
                     .Build();
  }
  // Make the aggregate
  std::unique_ptr<planner::AbstractPlanNode> agg2;
  execution::compiler::test::OutputSchemaHelper agg_out2{0, &expr_maker};
  {
    // Read previous layer's output
    auto c_name = hash_join_out3.GetOutput("c_name");
    auto c_custkey = hash_join_out3.GetOutput("c_custkey");
    auto o_orderkey = hash_join_out3.GetOutput("o_orderkey");
    auto o_orderdate = hash_join_out3.GetOutput("o_orderdate");
    auto o_totalprice = hash_join_out3.GetOutput("o_totalprice");
    auto l_quantity = hash_join_out3.GetOutput("l_quantity");
    // Make the aggregate expressions
    auto sum_qty = expr_maker.AggSum(l_quantity);
    // Add them to the helper.
    agg_out2.AddGroupByTerm("c_name", c_name);
    agg_out2.AddGroupByTerm("c_custkey", c_custkey);
    agg_out2.AddGroupByTerm("o_orderkey", o_orderkey);
    agg_out2.AddGroupByTerm("o_orderdate", o_orderdate);
    agg_out2.AddGroupByTerm("o_totalprice", o_totalprice);
    agg_out2.AddAggTerm("sum_qty", sum_qty);
    // Make the output schema
    agg_out2.AddOutput("c_name", agg_out2.GetGroupByTermForOutput("c_name"));
    agg_out2.AddOutput("c_custkey", agg_out2.GetGroupByTermForOutput("c_custkey"));
    agg_out2.AddOutput("o_orderkey", agg_out2.GetGroupByTermForOutput("o_orderkey"));
    agg_out2.AddOutput("o_orderdate", agg_out2.GetGroupByTermForOutput("o_orderdate"));
    agg_out2.AddOutput("o_totalprice", agg_out2.GetGroupByTermForOutput("o_totalprice"));
    agg_out2.AddOutput("sum_qty", agg_out2.GetAggTermForOutput("sum_qty"));
    auto schema = agg_out2.MakeSchema();
    // Make having
    // Build
    planner::AggregatePlanNode::Builder builder;
    agg2 = builder.SetOutputSchema(std::move(schema))
               .AddGroupByTerm(c_name)
               .AddGroupByTerm(c_custkey)
               .AddGroupByTerm(o_orderkey)
               .AddGroupByTerm(o_orderdate)
               .AddGroupByTerm(o_totalprice)
               .AddAggregateTerm(sum_qty)
               .AddChild(std::move(hash_join3))
               .SetAggregateStrategyType(planner::AggregateStrategyType::HASH)
               .SetHavingClausePredicate(nullptr)
               .Build();
  }
  // Order By
  std::unique_ptr<planner::AbstractPlanNode> order_by;
  execution::compiler::test::OutputSchemaHelper order_by_out{0, &expr_maker};
  {
    // Read previous layer
    auto c_name = agg_out2.GetOutput("c_name");
    auto c_custkey = agg_out2.GetOutput("c_custkey");
    auto o_orderkey = agg_out2.GetOutput("o_orderkey");
    auto o_orderdate = agg_out2.GetOutput("o_orderdate");
    auto o_totalprice = agg_out2.GetOutput("o_totalprice");
    auto sum_qty = agg_out2.GetOutput("sum_qty");
    order_by_out.AddOutput("c_name", c_name);
    order_by_out.AddOutput("c_custkey", c_custkey);
    order_by_out.AddOutput("o_orderkey", o_orderkey);
    order_by_out.AddOutput("o_orderdate", o_orderdate);
    order_by_out.AddOutput("o_totalprice", o_totalprice);
    order_by_out.AddOutput("sum_qty", sum_qty);
    auto schema = order_by_out.MakeSchema();
    // Order By Clause
    planner::SortKey clause1{o_totalprice, optimizer::OrderByOrderingType::DESC};
    planner::SortKey clause2{o_orderdate, optimizer::OrderByOrderingType::ASC};
    // Build
    planner::OrderByPlanNode::Builder builder;
    order_by = builder.SetOutputSchema(std::move(schema))
                   .AddChild(std::move(agg2))
                   .AddSortKey(clause1.first, clause1.second)
                   .AddSortKey(clause2.first, clause2.second)
                   .Build();
  }

  // Compile plan
  auto last_op = order_by.get();
  execution::exec::OutputPrinter printer(last_op->GetOutputSchema().Get());
  txn_ = txn_manager_->BeginTransaction();
  auto exec_ctx_q6 = execution::exec::ExecutionContext(
      db_oid_, common::ManagedPointer<transaction::TransactionContext>(txn_), printer, last_op->GetOutputSchema().Get(),
      common::ManagedPointer<catalog::CatalogAccessor>(accessor_), exec_settings_);

  auto query = execution::compiler::CompilationContext::Compile(*last_op, exec_settings_, accessor_.get());
  // Run Once to force compilation
  query->Run(common::ManagedPointer(&exec_ctx_q6), execution::vm::ExecutionMode::Interpret);
  // Only time execution
  for (auto _ : state) {
    query->Run(common::ManagedPointer(&exec_ctx_q6), execution::vm::ExecutionMode::Interpret);
  }
  txn_manager_->Commit(txn_, transaction::TransactionUtil::EmptyCallback, nullptr);
}

BENCHMARK_DEFINE_F(TPCHRunner, Q19)(benchmark::State &state) {
  execution::compiler::test::ExpressionMaker expr_maker;
  // Lineitem.
  auto l_table_oid = accessor_->GetTableOid("lineitem");
  const auto &l_schema = accessor_->GetSchema(l_table_oid);
  // Part.
  auto p_table_oid = accessor_->GetTableOid("part");
  const auto &p_schema = accessor_->GetSchema(p_table_oid);
  // Lineitem scan
  std::unique_ptr<planner::AbstractPlanNode> l_seq_scan;
  execution::compiler::test::OutputSchemaHelper l_seq_scan_out{1, &expr_maker};
  {
    // Read all needed columns
    auto l_extendedprice = expr_maker.CVE(l_schema.GetColumn("l_extendedprice").Oid(), type::TypeId::DECIMAL);
    auto l_discount = expr_maker.CVE(l_schema.GetColumn("l_discount").Oid(), type::TypeId::DECIMAL);
    auto l_partkey = expr_maker.CVE(l_schema.GetColumn("l_partkey").Oid(), type::TypeId::INTEGER);
    auto l_quantity = expr_maker.CVE(l_schema.GetColumn("l_quantity").Oid(), type::TypeId::DECIMAL);
    auto l_shipmode = expr_maker.CVE(l_schema.GetColumn("l_shipmode").Oid(), type::TypeId::VARCHAR);
    auto l_shipinstruct = expr_maker.CVE(l_schema.GetColumn("l_shipinstruct").Oid(), type::TypeId::VARCHAR);
    std::vector<catalog::col_oid_t> l_col_oids = {
        l_schema.GetColumn("l_extendedprice").Oid(), l_schema.GetColumn("l_discount").Oid(),
        l_schema.GetColumn("l_partkey").Oid(),       l_schema.GetColumn("l_quantity").Oid(),
        l_schema.GetColumn("l_shipmode").Oid(),      l_schema.GetColumn("l_shipinstruct").Oid()};
    // Make the output schema
    l_seq_scan_out.AddOutput("l_extendedprice", l_extendedprice);
    l_seq_scan_out.AddOutput("l_discount", l_discount);
    l_seq_scan_out.AddOutput("l_partkey", l_partkey);
    l_seq_scan_out.AddOutput("l_quantity", l_quantity);
    l_seq_scan_out.AddOutput("l_shipmode", l_shipmode);
    l_seq_scan_out.AddOutput("l_shipinstruct", l_shipinstruct);
    auto schema = l_seq_scan_out.MakeSchema();

    // Predicate.
    auto shipmode_comp = expr_maker.ConjunctionOr(expr_maker.ComparisonEq(l_shipmode, expr_maker.Constant("AIR")),
                                                  expr_maker.ComparisonEq(l_shipmode, expr_maker.Constant("AIR REG")));
    auto shipinstruct_comp = expr_maker.ComparisonEq(l_shipinstruct, expr_maker.Constant("DELIVER IN PERSON"));
    auto predicate = expr_maker.ConjunctionAnd(shipmode_comp, shipinstruct_comp);

    // Build
    planner::SeqScanPlanNode::Builder builder;
    l_seq_scan = builder.SetOutputSchema(std::move(schema))
                     .SetScanPredicate(predicate)
                     .SetTableOid(l_table_oid)
                     .SetColumnOids(std::move(l_col_oids))
                     .Build();
  }
  // Part Scan
  std::unique_ptr<planner::AbstractPlanNode> p_seq_scan;
  execution::compiler::test::OutputSchemaHelper p_seq_scan_out{0, &expr_maker};
  {
    // Read all needed columns
    auto p_brand = expr_maker.CVE(p_schema.GetColumn("p_brand").Oid(), type::TypeId::VARCHAR);
    auto p_container = expr_maker.CVE(p_schema.GetColumn("p_container").Oid(), type::TypeId::VARCHAR);
    auto p_partkey = expr_maker.CVE(p_schema.GetColumn("p_partkey").Oid(), type::TypeId::INTEGER);
    auto p_size = expr_maker.CVE(p_schema.GetColumn("p_size").Oid(), type::TypeId::INTEGER);
    std::vector<catalog::col_oid_t> p_col_oids = {
        p_schema.GetColumn("p_brand").Oid(), p_schema.GetColumn("p_container").Oid(),
        p_schema.GetColumn("p_partkey").Oid(), p_schema.GetColumn("p_size").Oid()};
    // Make the output schema
    p_seq_scan_out.AddOutput("p_brand", p_brand);
    p_seq_scan_out.AddOutput("p_container", p_container);
    p_seq_scan_out.AddOutput("p_partkey", p_partkey);
    p_seq_scan_out.AddOutput("p_size", p_size);
    auto schema = p_seq_scan_out.MakeSchema();
    // Build
    planner::SeqScanPlanNode::Builder builder;
    p_seq_scan = builder.SetOutputSchema(std::move(schema))
                     .SetScanPredicate(nullptr)
                     .SetTableOid(p_table_oid)
                     .SetColumnOids(std::move(p_col_oids))
                     .Build();
  }
  // Hash Join 1
  std::unique_ptr<planner::AbstractPlanNode> hash_join1;
  execution::compiler::test::OutputSchemaHelper hash_join_out1{0, &expr_maker};
  {
    // Left columns
    auto p_brand = p_seq_scan_out.GetOutput("p_brand");
    //auto p_container = p_seq_scan_out.GetOutput("p_container");
    auto p_partkey = p_seq_scan_out.GetOutput("p_partkey");
    auto p_size = p_seq_scan_out.GetOutput("p_size");
    // Right columns
    auto l_partkey = l_seq_scan_out.GetOutput("l_partkey");
    //auto l_quantity = l_seq_scan_out.GetOutput("l_quantity");
    auto l_discount = l_seq_scan_out.GetOutput("l_discount");
    auto l_extendedprice = l_seq_scan_out.GetOutput("l_extendedprice");
    // Output Schema
    hash_join_out1.AddOutput("l_extendedprice", l_extendedprice);
    hash_join_out1.AddOutput("l_discount", l_discount);
    hash_join_out1.AddOutput("p_brand", p_brand);
    hash_join_out1.AddOutput("p_size", p_size);
    auto schema = hash_join_out1.MakeSchema();
    // Predicate1
    execution::compiler::test::ExpressionMaker::ManagedExpression predicate1, predicate2, predicate3;
    auto gen_predicate_clause = [&](const std::string &brand, const std::vector<std::string> &sm, float lo_qty,
                                    float hi_qty, int32_t lo_size, int32_t hi_size) {
      auto brand_comp = expr_maker.ComparisonEq(p_brand, expr_maker.Constant(brand));
//      auto container_comp = expr_maker.ConjunctionOr(
//          expr_maker.ComparisonEq(p_container, expr_maker.Constant(sm[0])),
//          expr_maker.ConjunctionOr(
//              expr_maker.ComparisonEq(p_container, expr_maker.Constant(sm[1])),
//              expr_maker.ConjunctionOr(expr_maker.ComparisonEq(p_container, expr_maker.Constant(sm[2])),
//                                       expr_maker.ComparisonEq(p_container, expr_maker.Constant(sm[3])))));
//      auto qty_lo_comp = expr_maker.ComparisonGe(l_quantity, expr_maker.Constant(lo_qty));
//      auto qty_hi_comp = expr_maker.ComparisonLe(l_quantity, expr_maker.Constant(hi_qty));
//      auto qty_comp = expr_maker.ConjunctionAnd(qty_lo_comp, qty_hi_comp);
//      auto size_lo_comp = expr_maker.ComparisonGe(p_size, expr_maker.Constant(lo_size));
//      auto size_hi_comp = expr_maker.ComparisonLe(p_size, expr_maker.Constant(hi_size));
//      auto size_comp = expr_maker.ConjunctionAnd(size_lo_comp, size_hi_comp);
      return brand_comp;
//      return expr_maker.ConjunctionAnd(
//          brand_comp, expr_maker.ConjunctionAnd(container_comp, expr_maker.ConjunctionAnd(qty_comp, size_comp)));
    };
    predicate1 = gen_predicate_clause("Brand#12", {"SM CASE", "SM BOX", "SM PACK", "SM PKG"}, 1, 11, 1, 5);
//    predicate2 = gen_predicate_clause("Brand#23", {"MED BAG", "MED BOX", "MED PKG", "MED PACK"}, 10, 20, 1, 10);
//    predicate3 = gen_predicate_clause("Brand#34", {"LG CASE", "LG BOX", "LG PACK", "LG PKG"}, 20, 30, 1, 15);
    //auto predicate = expr_maker.ConjunctionOr(predicate1, expr_maker.ConjunctionOr(predicate2, predicate3));
    // Build
    planner::HashJoinPlanNode::Builder builder;
    hash_join1 = builder.AddChild(std::move(p_seq_scan))
                     .AddChild(std::move(l_seq_scan))
                     .SetOutputSchema(std::move(schema))
                     .AddLeftHashKey(p_partkey)
                     .AddRightHashKey(l_partkey)
                     .SetJoinType(planner::LogicalJoinType::INNER)
                     .SetJoinPredicate(predicate1)
                     .Build();
  }
//  // Make the aggregate
//  std::unique_ptr<planner::AbstractPlanNode> agg;
//  execution::compiler::test::OutputSchemaHelper agg_out{0, &expr_maker};
//  {
//    // Read previous layer's output
//    auto l_extendedprice = hash_join_out1.GetOutput("l_extendedprice");
//    auto l_discount = hash_join_out1.GetOutput("l_discount");
//    // Make the aggregate expressions
//    auto one_const = expr_maker.Constant(1.0f);
//    auto revenue = expr_maker.AggSum(expr_maker.OpMul(l_extendedprice, expr_maker.OpMin(one_const, l_discount)));
//    // Add them to the helper.
//    agg_out.AddAggTerm("revenue", revenue);
//    // Make the output schema
//    agg_out.AddOutput("revenue", agg_out.GetAggTermForOutput("revenue"));
//    auto schema = agg_out.MakeSchema();
//    // Make having
//    // Build
//    planner::AggregatePlanNode::Builder builder;
//    agg = builder.SetOutputSchema(std::move(schema))
//              .AddAggregateTerm(revenue)
//              .AddChild(std::move(hash_join1))
//              .SetAggregateStrategyType(planner::AggregateStrategyType::HASH)
//              .SetHavingClausePredicate(nullptr)
//              .Build();
//  }

  // Compile plan
  auto last_op = hash_join1.get();
  execution::exec::OutputPrinter printer(last_op->GetOutputSchema().Get());
  txn_ = txn_manager_->BeginTransaction();
  auto exec_ctx_q1 = execution::exec::ExecutionContext(
      db_oid_, common::ManagedPointer<transaction::TransactionContext>(txn_), printer, last_op->GetOutputSchema().Get(),
      common::ManagedPointer<catalog::CatalogAccessor>(accessor_), exec_settings_);

  auto query = execution::compiler::CompilationContext::Compile(*last_op, exec_settings_, accessor_.get());
  // Run Once to force compilation
  query->Run(common::ManagedPointer(&exec_ctx_q1), execution::vm::ExecutionMode::Interpret);
  // Only time execution
  for (auto _ : state) {
    query->Run(common::ManagedPointer(&exec_ctx_q1), execution::vm::ExecutionMode::Interpret);
  }
  txn_manager_->Commit(txn_, transaction::TransactionUtil::EmptyCallback, nullptr);
}

//
// BENCHMARK_DEFINE_F(TPCHRunner, SSB_Q1_1)(benchmark::State &state) {
//  execution::compiler::test::ExpressionMaker expr_maker
//  // Date
//  auto d_table_oid = accessor_->GetTableOid("ssbm.date");
//  const auto &d_schema = accessor_->GetSchema(d_table_oid);
//  // LineOrder
//  auto lo_table_oid = accessor_->GetTableOid("ssbm.lineorder");
//  const auto &lo_schema = accessor_->GetSchema(lo_table_oid);
//
//  // Scan date
//  std::unique_ptr<planner::AbstractPlanNode> d_seq_scan;
//  execution::compiler::test::OutputSchemaHelper d_seq_scan_out{0, &expr_maker};
//  {
//    auto d_datekey = expr_maker.CVE(d_schema.GetColumn("d_datekey").Oid(), type::TypeId::INTEGER);
//    auto d_year = expr_maker.CVE(d_schema.GetColumn("d_year").Oid(), type::TypeId::INTEGER);
//    std::vector<catalog::col_oid_t> d_col_oids = {
//        d_schema.GetColumn("d_datekey").Oid(), d_schema.GetColumn("d_year").Oid()
//    };
//    // Make the predicate: d_year=1993
//    auto _1993 = expr_maker.Constant(1993);
//    auto predicate = expr_maker.ComparisonEq(d_year, _1993);
//    // Make output schema.
//    d_seq_scan_out.AddOutput("d_datekey", d_datekey);
//    // Build plan node.
//    d_seq_scan = planner::SeqScanPlanNode::Builder{}
//        .SetOutputSchema(d_seq_scan_out.MakeSchema())
//        .SetScanPredicate(predicate)
//        .SetTableOid(d_table_oid)
//                     .SetColumnOids(std::move(d_col_oids))
//        .Build();
//  }
//
//  // Scan lineorder.
//  std::unique_ptr<planner::AbstractPlanNode> lo_seq_scan;
//  execution::compiler::test::OutputSchemaHelper lo_seq_scan_out{1, &expr_maker};
//  {
//    auto lo_orderdate =
//        expr_maker.CVE(lo_schema.GetColumn("lo_orderdate").Oid(), type::TypeId::INTEGER);
//    auto lo_extendedprice =
//        expr_maker.CVE(lo_schema.GetColumn("lo_extendedprice").Oid(), type::TypeId::INTEGER);
//    auto lo_discount =
//        expr_maker.CVE(lo_schema.GetColumn("lo_discount").Oid(), type::TypeId::INTEGER);
//    auto lo_quantity =
//        expr_maker.CVE(lo_schema.GetColumn("lo_quantity").Oid(), type::TypeId::INTEGER);
//    // Make predicate: lo_discount between 1 and 3 AND lo_quantity < 25
//    auto predicate = expr_maker.ConjunctionAnd(
//        expr_maker.CompareBetween(lo_discount, expr_maker.Constant(1), expr_maker.Constant(3)),
//        expr_maker.CompareLt(lo_quantity, expr_maker.Constant(25)));
//    // Make output schema.
//    lo_seq_scan_out.AddOutput("lo_orderdate", lo_orderdate);
//    lo_seq_scan_out.AddOutput("lo_extendedprice", lo_extendedprice);
//    lo_seq_scan_out.AddOutput("lo_discount", lo_discount);
//    // Build plan node.
//    planner::SeqScanPlanNode::Builder builder;
//    lo_seq_scan = builder.SetOutputSchema(lo_seq_scan_out.MakeSchema())
//        .SetScanPredicate(predicate)
//        .SetTableOid(lo_table->GetId())
//        .Build();
//  }
//
//  // date <-> lineorder join.
//  std::unique_ptr<planner::AbstractPlanNode> hash_join;
//  planner::OutputSchemaHelper hash_join_out{&expr_maker, 0};
//  {
//    // Left columns.
//    auto d_datekey = d_seq_scan_out.GetOutput("d_datekey");
//    // Right columns.
//    auto lo_orderdate = lo_seq_scan_out.GetOutput("lo_orderdate");
//    auto lo_extendedprice = lo_seq_scan_out.GetOutput("lo_extendedprice");
//    auto lo_discount = lo_seq_scan_out.GetOutput("lo_discount");
//    // Output Schema
//    hash_join_out.AddOutput("lo_extendedprice", lo_extendedprice);
//    hash_join_out.AddOutput("lo_discount", lo_discount);
//    // Build
//    planner::HashJoinPlanNode::Builder builder;
//    hash_join = builder.AddChild(std::move(d_seq_scan))
//        .AddChild(std::move(lo_seq_scan))
//        .SetOutputSchema(hash_join_out.MakeSchema())
//        .AddLeftHashKey(d_datekey)
//        .AddRightHashKey(lo_orderdate)
//        .SetJoinType(planner::LogicalJoinType::INNER)
//        .SetJoinPredicate(expr_maker.CompareEq(d_datekey, lo_orderdate))
//        .Build();
//  }
//
//  // Make the aggregate
//  std::unique_ptr<planner::AbstractPlanNode> agg;
//  planner::OutputSchemaHelper agg_out{&expr_maker, 0};
//  {
//    // Read previous layer's output
//    auto lo_extendedprice = hash_join_out.GetOutput("lo_extendedprice");
//    auto lo_discount = hash_join_out.GetOutput("lo_discount");
//    auto revenue = expr_maker.AggSum(expr_maker.OpMul(lo_extendedprice, lo_discount));
//    // Add them to the helper.
//    agg_out.AddAggTerm("revenue", revenue);
//    // Make the output schema.
//    agg_out.AddOutput("revenue", agg_out.GetAggTermForOutput("revenue"));
//    // Build plan node.
//    planner::AggregatePlanNode::Builder builder;
//    agg = builder.SetOutputSchema(agg_out.MakeSchema())
//        .AddAggregateTerm(revenue)
//        .AddChild(std::move(hash_join))
//        .SetAggregateStrategyType(planner::AggregateStrategyType::PLAIN)
//        .SetHavingClausePredicate(nullptr)
//        .Build();
//  }
//
//  // Compile plan!
//  auto query = CompilationContext::Compile(*agg);
//
//  // Run Once to force compilation
//  NoOpResultConsumer consumer;
//  {
//    sql::MemoryPool memory(nullptr);
//    sql::ExecutionContext exec_ctx(&memory, agg->GetOutputSchema(), &consumer);
//    query->Run(&exec_ctx, vm::ExecutionMode::Compiled);
//  }
//
//  // Only time execution.
//  for (auto _ : state) {
//    sql::MemoryPool memory(nullptr);
//    sql::ExecutionContext exec_ctx(&memory, agg->GetOutputSchema(), &consumer);
//    query->Run(&exec_ctx, vm::ExecutionMode::Compiled);
//  }
//}

//BENCHMARK_REGISTER_F(TPCHRunner, Q16)->Unit(benchmark::kMillisecond)->UseManualTime()->Iterations(1);
// BENCHMARK_REGISTER_F(TPCHRunner, Q18)->Unit(benchmark::kMillisecond)->UseManualTime()->Iterations(1);
 BENCHMARK_REGISTER_F(TPCHRunner, Q19)->Unit(benchmark::kMillisecond)->UseManualTime()->Iterations(1);
}  // namespace terrier::runner
