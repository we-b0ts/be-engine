//! Global scalar formats and native domain proofs are independent constraints
//! on one leaf. Both validate within the same staged pairing decision.
use super::*;

impl Comparator<'_> {
    pub(super) fn global_native_leaf(
        &mut self,
        context: LeafContext<'_>,
        nodes: (Node<'_>, Node<'_>),
        selected: usize,
        native_indices: &[usize],
        verified_indices: &[usize],
        decisions: &mut Decisions,
    ) -> Result<(), Difference> {
        let mut staged = decisions.clone();
        let field = &self.fields[selected];
        let contract = if let FieldContract::Conditional { when, contract } = field.contract {
            let active = when
                .matches_pair(
                    context.source_root,
                    context.target_root,
                    context.source_pointer,
                    context.target_pointer,
                )
                .map_err(|_| {
                    difference(context.source_pointer, "global exact format branch changed")
                })?;
            if !active {
                if context.source != context.target {
                    return Err(difference(
                        context.source_pointer,
                        "global exact format requires equal values",
                    ));
                }
                None
            } else {
                Some(contract.as_ref())
            }
        } else {
            Some(field.contract)
        };
        match contract {
            Some(FieldContract::Exact) => {
                if context.source != context.target {
                    return Err(difference(
                        context.source_pointer,
                        "exact field contract requires equal values",
                    ));
                }
            }
            Some(FieldContract::IdentityAnchor) => {
                if context.source != context.target {
                    return Err(difference(
                        context.source_pointer,
                        "exact identity value changed",
                    ));
                }
                staged
                    .identities
                    .observe(context.source, context.target)
                    .map_err(|reason| difference(context.source_pointer, reason))?;
            }
            Some(contract) => {
                let definition = contract.registered_definition(true).ok_or_else(|| {
                    difference(
                        context.source_pointer,
                        "global/native composition requires a scalar format",
                    )
                })?;
                self.registered_policy(
                    &definition,
                    field,
                    nodes.0,
                    nodes.1,
                    context.source_pointer,
                    context.target_pointer,
                    &mut staged,
                    0,
                )?;
            }
            None => {}
        }
        staged.selected.insert(selected);
        staged.evaluated.insert(field.rule_id.into());
        for &index in native_indices {
            let field = &self.native[index];
            native::compare(
                context.source,
                context.target,
                field,
                context.source_pointer,
                context.clocks,
                &mut staged,
            )?;
            staged.selected_native.insert(index);
            staged.evaluated.insert(field.rule_id.into());
        }
        for &index in verified_indices {
            let field = &self.verified[index];
            native::verify(field, context, &mut staged)?;
            staged.selected_native.insert(self.native.len() + index);
            staged.evaluated.insert(field.rule_id.into());
        }
        *decisions = staged;
        Ok(())
    }
}
