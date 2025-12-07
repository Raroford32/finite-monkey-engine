[EXPLICIT_INVARIANT] 资产精度必须严格限制在协议定义的范围内，即任何被列入的资产必须满足 MIN_ALLOWED_UNDERLYING_DECIMALS ≤ 资产小数位 ≤ MAX_ALLOWED_UNDERLYING_DECIMALS 这个不变量，代码中必须在资产列入时验证此条件，超出此范围的资产无法被列入，如果允许超出范围的资产被添加可能导致精度溢出、计算错误或资金损失。
<|INVARIANT_SPLIT|>
[EXPLICIT_INVARIANT] 抵押品风险评分必须受协议硬性上限约束，即使治理角色被信任，代码层面也必须强制执行 0 ≤ collateralFactor ≤ MAX_ALLOWED_RISK，任何设置或更新风险评分的函数都必须验证此不变量，防止治理设置超过协议上限的风险评分，如果此约束被违反可能导致抵押不足和协议坏账。
<|INVARIANT_SPLIT|>
[EXPLICIT_INVARIANT] 清算奖金必须满足协议定义的下限约束，即 maxLiquidationBonus ≥ PROTOCOL_MIN_LIQUIDATION_BONUS 必须在所有清算奖金设置和更新时得到验证，过低的清算奖金可能导致清算人缺乏激励，使得不健康的仓位无法被及时清算，从而危及协议的偿付能力。
<|INVARIANT_SPLIT|>
[EXPLICIT_INVARIANT] 清算奖金与风险评分的乘积必须满足全局上限约束，即 maxLiquidationBonus × collateralFactor ≤ GLOBAL_UPPER_LIMIT 这个不变量必须在任何修改清算参数或风险评分的操作中得到验证，违反此约束可能导致清算人获得过高奖励，造成被清算用户的不公平损失或协议资金外流。
<|INVARIANT_SPLIT|>
[EXPLICIT_INVARIANT] 清算费用必须受协议最大值限制，即 liquidationFee ≤ PROTOCOL_MAX_LIQUIDATION_FEE 必须在所有设置清算费用的函数中得到强制执行，即使是治理操作也不能绕过此硬性限制，过高的清算费用会损害用户利益并可能导致协议被认为不公平而失去用户信任。
