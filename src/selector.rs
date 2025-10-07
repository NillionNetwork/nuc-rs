use std::{
    collections::{HashMap, HashSet},
    fmt,
    str::FromStr,
    sync::LazyLock,
};

use serde_with::{DeserializeFromStr, SerializeDisplay};

static LABEL_ALPHABET: LazyLock<HashSet<char>> =
    LazyLock::new(|| ('a'..='z').chain('A'..='Z').chain('0'..='9').chain(['_', '-']).collect());

/// The target of a selector.
#[derive(Clone, Debug, PartialEq)]
enum SelectorTarget {
    /// The target is the token itself.
    Token,

    /// The target is the external context.
    Context,
}

/// A selector that can be applied to a Nuc.
#[derive(Clone, Debug, PartialEq, SerializeDisplay, DeserializeFromStr)]
pub struct Selector {
    labels: Vec<String>,
    target: SelectorTarget,
}

impl Selector {
    /// Applies this selector to a value and context, returning the selected value.
    pub fn apply<'a>(
        &self,
        value: &'a serde_json::Value,
        context: &'a HashMap<&str, serde_json::Value>,
    ) -> &'a serde_json::Value {
        match &self.target {
            SelectorTarget::Token => Self::apply_on_value(&self.labels, value),
            SelectorTarget::Context => match self.labels.first() {
                Some(label) => {
                    // Use the first label look up which entry in the context we should be using.
                    let Some(value) = context.get(label.as_str()) else {
                        return &serde_json::Value::Null;
                    };
                    // And the rest of the labels to do the actual matching.
                    Self::apply_on_value(&self.labels[1..], value)
                }
                // this can't actually happen since we must have labels when using the context
                None => &serde_json::Value::Null,
            },
        }
    }

    fn apply_on_value<'a>(labels: &[String], mut value: &'a serde_json::Value) -> &'a serde_json::Value {
        for label in labels {
            match value.get(label) {
                Some(inner) => value = inner,
                None => return &serde_json::Value::Null,
            };
        }
        value
    }
}

impl FromStr for Selector {
    type Err = SelectorParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Consume the optional $ and pick our target.
        let (target, s) = match s.strip_prefix("$") {
            Some(rest) => (SelectorTarget::Context, rest),
            None => (SelectorTarget::Token, s),
        };
        // At this point it must start with "."
        let Some(s) = s.strip_prefix('.') else {
            return Err(SelectorParseError::MissingPrefix);
        };
        if s.is_empty() {
            return match &target {
                SelectorTarget::Token => Ok(Self { labels: Vec::new(), target }),
                SelectorTarget::Context => Err(SelectorParseError::ContextNeedsPath),
            };
        }

        let mut labels = Vec::new();
        for label in s.split(".") {
            if !label.chars().all(|c| LABEL_ALPHABET.contains(&c)) {
                return Err(SelectorParseError::Alphabet);
            } else if label.is_empty() {
                return Err(SelectorParseError::Empty);
            }
            labels.push(label.to_string());
        }

        Ok(Self { labels, target })
    }
}

impl fmt::Display for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let SelectorTarget::Context = &self.target {
            write!(f, "$")?;
        }
        if self.labels.is_empty() {
            return write!(f, ".");
        }
        for label in &self.labels {
            write!(f, ".{label}")?;
        }
        Ok(())
    }
}

/// An error encountered when parsing a selector.
#[derive(Debug, thiserror::Error)]
pub enum SelectorParseError {
    /// The selector contains an invalid character.
    #[error("invalid attribute character")]
    Alphabet,

    /// The selector contains an empty attribute.
    #[error("empty attribute")]
    Empty,

    /// The selector is missing the required prefix.
    #[error("selector must start with '.' or '$.'")]
    MissingPrefix,

    /// A context selector requires a path.
    #[error("context selector needs path")]
    ContextNeedsPath,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::{Value, json};

    #[rstest]
    #[case::token_identity(".", &[], SelectorTarget::Token)]
    #[case::token_single(".foo", &["foo"], SelectorTarget::Token)]
    #[case::context_single("$.foo", &["foo"], SelectorTarget::Context)]
    #[case::token_multi(".foo.bar", &["foo", "bar"], SelectorTarget::Token)]
    #[case::context_multi("$.foo.bar", &["foo", "bar"], SelectorTarget::Context)]
    #[case::entire_alphabet(
        ".abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
        &["abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"],
        SelectorTarget::Token
    )]
    fn parse_valid_selectors(#[case] input: &str, #[case] path: &[&str], #[case] target: SelectorTarget) {
        let parsed: Selector = input.parse().expect("parse failed");
        assert_eq!(parsed.labels, path);
        assert_eq!(parsed.target, target);

        let output = parsed.to_string();
        assert_eq!(output, input);
    }

    #[rstest]
    #[case::empty("")]
    #[case::empty_context("$")]
    #[case::context_idenitty("$.")]
    #[case::no_leading_dot("A")]
    #[case::invalid_field_name1(".#")]
    #[case::invalid_field_name2(".🚀")]
    #[case::invalid_field_name3("$.#")]
    #[case::invalid_field_name4("$.$")]
    #[case::trailing_dot1(".A.")]
    #[case::trailing_dot2("$.A.")]
    #[case::empty_label1(".A..B")]
    #[case::empty_label2("$.A..B")]
    fn parse_invalid_selectors(#[case] input: &str) {
        input.parse::<Selector>().expect_err("parse succeeded");
    }

    #[rstest]
    #[case::identity(".", json!({"foo": 42}), json!({"foo": 42}))]
    #[case::field(".foo", json!({"foo": 42}), json!(42))]
    #[case::nested(".foo.bar", json!({"foo": {"bar": 42}}), json!(42))]
    #[case::non_existent(".foo", json!({"bar": 42}), Value::Null)]
    fn token_lookup(#[case] expr: &str, #[case] input: Value, #[case] expected: Value) {
        let expr: Selector = expr.parse().expect("invalid expression");
        let context = Default::default();
        let output = expr.apply(&input, &context);
        assert_eq!(output, &expected);
    }

    #[rstest]
    #[case::entire_context_arg1("$.req", json!({"foo": 42, "bar": "zar"}))]
    #[case::entire_context_arg2("$.other", json!(1337))]
    #[case::nested1("$.req.foo", json!(42))]
    #[case::non_existent("$.foo", Value::Null)]
    #[case::non_existent_subkey("$.req.choochoo", Value::Null)]
    fn context_lookup(#[case] expr: &str, #[case] expected: Value) {
        let expr: Selector = expr.parse().expect("invalid expression");
        let input = json!({});
        let context = HashMap::from([("req", json!({"foo": 42, "bar": "zar"})), ("other", json!(1337))]);
        let output = expr.apply(&input, &context);
        assert_eq!(output, &expected);
    }
}
