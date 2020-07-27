#include "test_util/tpch/workload.h"

#include <random>

#include "common/managed_pointer.h"
#include "execution/exec/execution_context.h"
#include "execution/execution_util.h"
#include "execution/sql/value_util.h"
#include "execution/table_generator/table_generator.h"
#include "main/db_main.h"

namespace terrier::tpch {

Workload::Workload(common::ManagedPointer<DBMain> db_main, const std::string &db_name, const std::string &table_root, transaction::TransactionContext * txn,
                   execution::exec::ExecutionContext *exec_ctx) {
  // cache db main and members
  db_main_ = db_main;
  txn_manager_ = db_main_->GetTransactionLayer()->GetTransactionManager();
  block_store_ = db_main_->GetStorageLayer()->GetBlockStore();
  catalog_ = db_main_->GetCatalogLayer()->GetCatalog();
  txn_manager_ = db_main_->GetTransactionLayer()->GetTransactionManager();


  // create the TPCH database and compile the queries
  GenerateTPCHTables(exec_ctx, table_root);
  // LoadTPCHQueries(&exec_ctx, queries);

  // Initialize the TPCH outputs
  sample_output_.InitTestOutput();

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


std::vector<parser::ConstantValueExpression> Workload::GetQueryParams(const std::string &query_name) {
  std::vector<parser::ConstantValueExpression> params;
  params.reserve(8);

  // Add the identifier for each pipeline. At most 8 query pipelines for now
  for (int i = 0; i < 8; ++i) {
    const std::string query_val = query_name + "_p" + std::to_string(i + 1);

    auto string_val = execution::sql::ValueUtil::CreateStringVal(query_val);
    params.emplace_back(type::TypeId::VARCHAR, string_val.first, std::move(string_val.second));
  }

  return params;
}


}  // namespace terrier::tpch
