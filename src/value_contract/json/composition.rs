//! Global scalar formats and native domain proofs are independent constraints
//! on one leaf. Both validate within the same staged pairing decision.
use super::*;

impl Comparator<'_> {
    pub(super) fn global_native_leaf(
        &self,
        context: LeafContext<'_>,
        selected: (usize, &Field<'_>),
        native_fields: &[(usize, &NativeField<'_>)],
        verified_fields: &[(usize, &VerifiedField<'_>)],
        decisions: &mut Decisions,
    ) -> Result<(), Difference> {
        let mut staged = decisions.clone();
        let (index, field) = selected;
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
            Some(FieldContract::Identity { prefix, format }) => identity::compare(
                context.source,
                context.target,
                prefix,
                *format,
                context.source_pointer,
                &mut staged,
            )?,
            Some(contract @ FieldContract::Time { .. }) => {
                if context.source != context.target {
                    self.time_field(
                        context.source,
                        context.target,
                        context.source_pointer,
                        context.target_pointer,
                        field,
                        contract,
                        &mut staged,
                    )?;
                }
            }
            Some(FieldContract::Duration { unit, anchor }) => {
                if context.source != context.target {
                    compare_duration(
                        context.source,
                        context.target,
                        *unit,
                        context.clocks.get(*anchor),
                    )
                    .map_err(|error| difference(context.source_pointer, &error.to_string()))?;
                }
            }
            None => {}
            _ => {
                return Err(difference(
                    context.source_pointer,
                    "global/native composition requires a scalar format",
                ));
            }
        }
        staged.selected.insert(index);
        staged.evaluated.insert(field.rule_id.into());
        for (index, field) in native_fields {
            native::compare(
                context.source,
                context.target,
                field,
                context.source_pointer,
                context.clocks,
                &mut staged,
            )?;
            staged.selected_native.insert(*index);
            staged.evaluated.insert(field.rule_id.into());
        }
        for (index, field) in verified_fields {
            native::verify(field, context, &mut staged)?;
            staged.selected_native.insert(self.native.len() + *index);
            staged.evaluated.insert(field.rule_id.into());
        }
        *decisions = staged;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
