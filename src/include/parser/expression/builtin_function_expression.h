#pragma once

#include <memory>
#include <utility>
#include <vector>

#include "execution/ast/builtins.h"
#include "execution/sql/generic_value.h"
#include "parser/expression/abstract_expression.h"

namespace terrier::parser {

/**
 * Represents a builtin function call.
 */
class BuiltinFunctionExpression : public terrier::parser::AbstractExpression {
 public:
  /**
   * Instantiate a new constant value expression.
   * @param value value to be held
   */
  explicit BuiltinFunctionExpression(terrier::execution::ast::Builtin builtin,
                                     std::vector<std::unique_ptr<AbstractExpression>> &&children,
                                     const terrier::type::TypeId return_value_type)
      : AbstractExpression(terrier::parser::ExpressionType::BUILTIN_FUNCTION, return_value_type,
                           std::move(children)),
        builtin_(builtin) {}

  terrier::execution::ast::Builtin GetBuiltin() const { return builtin_; }

  /**
 * Copies this ConstantValueExpression
 * @returns copy of this
 */
  std::unique_ptr<AbstractExpression> Copy() const override {
    return std::unique_ptr<AbstractExpression>{std::make_unique<BuiltinFunctionExpression>(*this)};
  }

  /**
 * Creates a copy of the current AbstractExpression with new children implanted.
 * The children should not be owned by any other AbstractExpression.
 * @param children New children to be owned by the copy
 * @returns copy of this with new children
 */
  std::unique_ptr<AbstractExpression> CopyWithChildren(
      std::vector<std::unique_ptr<AbstractExpression>> &&children) const override {
    TERRIER_ASSERT(children.empty(), "ConstantValueExpression should have 0 children");
    return Copy();
  }
  void Accept(common::ManagedPointer<binder::SqlNodeVisitor> v) override { v->Visit(common::ManagedPointer(this)); }

 private:
  terrier::execution::ast::Builtin builtin_;
};

}  // namespace tpl::sql::planner
