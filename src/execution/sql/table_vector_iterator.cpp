#include "execution/sql/table_vector_iterator.h"

#include <limits>
#include <numeric>
#include <utility>
#include <vector>

#include "execution/exec/execution_context.h"
#include "execution/sql/column_vector_iterator.h"
#include "execution/sql/thread_state_container.h"
#include "execution/util/timer.h"
#include "loggers/execution_logger.h"
#include "tbb/parallel_for.h"
#include "tbb/task_scheduler_init.h"

namespace terrier::execution::sql {

TableVectorIterator::TableVectorIterator(exec::ExecutionContext *exec_ctx, uint32_t table_oid, uint32_t *col_oids,
                                         uint32_t num_oids)
    : exec_ctx_(exec_ctx), table_oid_(table_oid), col_oids_(col_oids, col_oids + num_oids) {}

TableVectorIterator::~TableVectorIterator() = default;

bool TableVectorIterator::Init() {
  // No-op if already initialized
  if (IsInitialized()) {
    return true;
  }

  // Set up the table and the iterator.
  table_ = exec_ctx_->GetAccessor()->GetTable(table_oid_);
  TERRIER_ASSERT(table_ != nullptr, "Table must exist!!");
  iter_ = std::make_unique<storage::DataTable::SlotIterator>(table_->begin());
  const auto &table_col_map = table_->GetColumnMap();

  // Configure the vector projection, create the column iterators.
  std::vector<storage::col_id_t> col_ids;
  std::vector<TypeId> col_types(col_oids_.size());
  column_iterators_.reserve(col_oids_.size());
  for (uint64_t idx = 0; idx < col_oids_.size(); idx++) {
    auto col_oid = col_oids_[idx];
    auto col_type = GetTypeId(table_col_map.at(col_oid).col_type_);
    auto storage_col_id = table_col_map.at(col_oid).col_id_;

    col_ids.emplace_back(storage_col_id);
    col_types[idx] = col_type;
    column_iterators_.emplace_back(GetTypeIdSize(col_type));
  }

  // Create an owning vector.
  vector_projection_.SetStorageColIds(col_ids);
  vector_projection_.Initialize(col_types);
  vector_projection_.Reset(common::Constants::K_DEFAULT_VECTOR_SIZE);

  // All good.
  initialized_ = true;
  return true;
}

bool TableVectorIterator::Init(uint32_t block_start, uint32_t block_end) {
  // TODO(WAN): code duplication. Though it does make it pretty clear.

  // No-op if already initialized
  if (IsInitialized()) {
    return true;
  }

  // Set up the table and the iterator.
  table_ = exec_ctx_->GetAccessor()->GetTable(table_oid_);
  TERRIER_ASSERT(table_ != nullptr, "Table must exist!!");
  iter_ = std::make_unique<storage::DataTable::SlotIterator>(table_->GetBlockedSlotIterator(block_start, block_end));
  const auto &table_col_map = table_->GetColumnMap();

  // Configure the vector projection, create the column iterators.
  std::vector<storage::col_id_t> col_ids;
  std::vector<TypeId> col_types(col_oids_.size());
  column_iterators_.reserve(col_oids_.size());
  for (uint64_t idx = 0; idx < col_oids_.size(); idx++) {
    auto col_oid = col_oids_[idx];
    auto col_type = GetTypeId(table_col_map.at(col_oid).col_type_);
    auto storage_col_id = table_col_map.at(col_oid).col_id_;

    col_ids.emplace_back(storage_col_id);
    col_types[idx] = col_type;
    column_iterators_.emplace_back(GetTypeIdSize(col_type));
  }

  // Create an owning vector.
  vector_projection_.SetStorageColIds(col_ids);
  vector_projection_.Initialize(col_types);
  vector_projection_.Reset(common::Constants::K_DEFAULT_VECTOR_SIZE);

  // All good.
  initialized_ = true;
  return true;
}

void TableVectorIterator::RefreshVectorProjection() {
  // Reset our projection and refresh all columns with new data from the column iterators.

  const uint32_t tuple_count = column_iterators_[0].GetTupleCount();

  TERRIER_ASSERT(std::all_of(column_iterators_.begin(), column_iterators_.end(),
                             [&](const auto &iter) { return tuple_count == iter.GetTupleCount(); }),
                 "Not all iterators have the same size?");

  vector_projection_.Reset(tuple_count);
  for (uint64_t col_idx = 0; col_idx < column_iterators_.size(); col_idx++) {
    Vector *column_vector = vector_projection_.GetColumn(col_idx);
    column_vector->Reference(column_iterators_[col_idx].GetColumnData(),
                             column_iterators_[col_idx].GetColumnNullBitmap(),
                             column_iterators_[col_idx].GetTupleCount());
  }
  vector_projection_.CheckIntegrity();

  // Insert our vector projection instance into the vector projection iterator.
  vector_projection_iterator_.SetVectorProjection(&vector_projection_);
}

bool TableVectorIterator::Advance() {
  // Cannot advance if not initialized.
  if (!IsInitialized()) {
    return false;
  }

  // If the iterator is out of data, then we are done.
  if (*iter_ == table_->end() || (**iter_).GetBlock() == nullptr) {
    return false;
  }

  // Otherwise, scan the table to set the vector projection.
  table_->Scan(exec_ctx_->GetTxn(), iter_.get(), &vector_projection_);
  vector_projection_iterator_.SetVectorProjection(&vector_projection_);

  return true;
}

namespace {

class ScanTask {
 public:
  ScanTask(uint32_t table_oid, uint32_t *col_oids, uint32_t num_oids, void *const query_state,
           exec::ExecutionContext *exec_ctx, TableVectorIterator::ScanFn scanner)
      : exec_ctx_(exec_ctx),
        table_oid_(table_oid),
        col_oids_(col_oids),
        num_oids_(num_oids),
        query_state_(query_state),
        thread_state_container_(exec_ctx->GetThreadStateContainer()),
        scanner_(scanner) {}

  void operator()(const tbb::blocked_range<uint32_t> &block_range) const {
    // Create the iterator over the specified block range
    TableVectorIterator iter{exec_ctx_, table_oid_, col_oids_, num_oids_};

    // Initialize it
    if (!iter.Init(block_range.begin(), block_range.end())) {
      return;
    }

    // Pull out the thread-local state
    byte *const thread_state = thread_state_container_->AccessCurrentThreadState();

    // Call scanning function
    scanner_(query_state_, thread_state, &iter, exec_ctx_);
  }

 private:
  exec::ExecutionContext *exec_ctx_;
  uint32_t table_oid_;
  uint32_t *col_oids_;
  uint32_t num_oids_;
  void *const query_state_;
  ThreadStateContainer *const thread_state_container_;
  TableVectorIterator::ScanFn scanner_;
};

}  // namespace

bool TableVectorIterator::ParallelScan(uint32_t table_oid, uint32_t *col_oids, uint32_t num_oids,
                                       void *const query_state, exec::ExecutionContext *exec_ctx,
                                       const TableVectorIterator::ScanFn scan_fn, const uint32_t min_grain_size) {
  // Lookup table
  const auto table = exec_ctx->GetAccessor()->GetTable(catalog::table_oid_t{table_oid});
  if (table == nullptr) {
    return false;
  }

  // Time
  util::Timer<std::milli> timer;
  timer.Start();

  // Execute parallel scan
  tbb::task_scheduler_init scan_scheduler;
  tbb::blocked_range<uint32_t> block_range(0, table->table_.data_table_->GetNumBlocks(), min_grain_size);
  tbb::parallel_for(block_range, ScanTask(table_oid, col_oids, num_oids, query_state, exec_ctx, scan_fn));

  timer.Stop();

  double tps = table->GetNumTuple() / timer.GetElapsed() / 1000.0;
  EXECUTION_LOG_INFO("Scanned {} blocks ({} tuples) in {} ms ({:.3f} mtps)", table->table_.data_table_->GetNumBlocks(),
                     table->GetNumTuple(), timer.GetElapsed(), tps);

  return true;
}
}  // namespace terrier::execution::sql
