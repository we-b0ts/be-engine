# JSON 使用规范

目标 Rust 项目统一通过 `brz-json` 使用 JSON 能力。保留 Serde 的
`Serialize` / `Deserialize` 派生与字段属性，避免直接依赖、导入或调用
`serde_json::*`（下述存量动态修改边界除外）。避免在项目中重复实现
缺失/null、宽松转换、原样透传等通用逻辑。

使用固定发布版本，例如 `brz-json = "=0.0.9"`。联调可按用户要求临时使用
`path` 依赖；交付时切回发布版本并更新锁文件。

## 类型选择

- 已知结构：优先 `struct`，用 `brz_json::from_str` / `from_slice` 和
  `to_string` / `to_vec`；分片 HTTP 输入继续用 `JsonReader`。
- 不读取内容、需要原样透传：用 `brz_json::RawJson`，借用输入使用 `RawJsonRef<'a>`。
  借用字段加 `#[serde(borrow)]`；保留 Reader 生命周期。
- 历史 JSON 需要 Value 的数值校验和规范化：用 `OpaqueJson`。
  `decode::<T>()` 返回错误，`project::<T>()` 明确容忍投影不匹配。
  `RawJson` 可以保留 `1e400`，`OpaqueJson` 反序列化会拒绝它，迁移时不能混用。
- 动态键且需保持顺序：用 `Object<T>`。存量代码确需动态修改 schema-free
  文档时，可保留边界内的 `serde_json::Value`，不要只换 import。

`brz-json` 不重导出 `Value`、`Map`、`Number`、`json!` 或 `RawValue`。
`RawJson` 负责校验、原样序列化与 `decode::<T>()` 类型投影；`RawJsonRef`
支持 Reader 借用和 `to_owned()`。底层 `RawValue` 留在模块内部。
新需求出现后再补充有实际处理逻辑的能力，避免预先增加同义包装。

## 缺失与 null

普通 `Option<T>` 同时表示缺失和 null。需要分别处理的更新请求使用宏，
业务字段声明实际类型，不直接声明内部 `Field<T>`：

```rust
use brz_json::FieldState as _;
use serde::{Deserialize, Serialize};

#[brz_json::model]
#[derive(Default, Deserialize, Serialize)]
struct Update {
    #[json(presence)]
    title: String,
}
```

通过 `title.is_missing()`、`is_null()`、`is_present()`、`value()` 或
`into_value()` 查询状态和值。缺失字段序列化时省略，显式 null 保留。
宏放在 derive 前面；普通结构体无需添加 `model`。
只有源协议明确允许错误类型时才加 `#[json(presence, lenient)]`，这时错误类型
属于“已提供、非 null、无有效值”。不要把它当成缺失。

## 兼容策略按字段选择

使用 `#[serde(default, deserialize_with = "brz_json::adapters::...")]`：

| 源行为 | adapter |
| --- | --- |
| null 使用默认值，错误类型报错 | `null_as_default` |
| 错误类型忽略 / 使用默认值 | `try_decode` / `invalid_as_default` |
| 模型必须是对象，拒绝位置数组 | `object` / `optional_object` / `optional_objects` |
| null 或空字符串不保留 | `nonempty_string` |
| 列表只过滤 null，其他错误元素报错 | `nonnull_items` |
| 字符串、bool、整数浮点等显式转换 | `integer` / `number` / `boolean` 及 `optional_*` |
| 明确需要浮点截断 | `truncated_integer` |
| 历史 trim、空字符串、任意有符号整数布尔策略 | `legacy_boolean` |
| Python `bool(value)` | `PythonTruthiness` / `python_truthy` |

`default` 只控制缺失，adapter 控制已提供值；不全局启用宽松转换。
容错仍须完整校验 JSON，语法错误不能吞掉。业务默认值、枚举、权限、错误响应和
特殊 Python 格式化留在业务项目。错误诊断可读 `path()` 和可用的 `byte_offset()`。

迁移保留缺失、null、错误类型、空值和数值边界语义。通用测试由 JSON 模块覆盖后，
可移除项目中重复的能力测试，保留业务响应和状态转换测试。
