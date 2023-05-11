use cosmwasm_std::{attr, Attribute};

pub fn method_attrs<A: Into<Attribute>>(
    method: &str,
    attrs: impl IntoIterator<Item = A>,
) -> Vec<Attribute> {
    let mut res = vec![attr("method", method)];
    res.extend(attrs.into_iter().map(A::into));

    res
}
