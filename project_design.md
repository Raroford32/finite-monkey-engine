一、ERC合规性与代币标准
EIP/ERC合规要求
EIP-712实现:

用于Spoke的setUserPositionManager意图的类型化签名
用于通过签名网关处理的所有意图
验证标准: EIP违规问题必须至少达到中等严重性才有效
ERC-20代币要求:

仅接受明确列入白名单的ERC20代币
必须完全符合ERC20标准,无非标准钩子
明确禁止:
ERC777代币(带回调机制)
转账费用代币(fee-on-transfer)
重定基代币(rebasing tokens)
反射代币(reflection tokens)
任何余额突变副作用的代币
三、配置硬性限制
治理可配置但有硬性上限的参数
尽管治理角色被信任,但协议在代码层面强制执行以下限制:

1. 资产精度限制
MIN_ALLOWED_UNDERLYING_DECIMALS ≤ 资产小数位 ≤ MAX_ALLOWED_UNDERLYING_DECIMALS

超出此范围的资产无法被列入
2. 抵押品风险评分 (collateralFactor)
basic
0 ≤ collateralFactor ≤ MAX_ALLOWED_RISK (协议定义的上限)

防止治理设置超过协议上限的风险评分
3. 清算参数限制
最大清算奖金:

maxLiquidationBonus ≥ PROTOCOL_MIN_LIQUIDATION_BONUS

清算奖金与风险评分的乘积:

maxLiquidationBonus × collateralFactor ≤ GLOBAL_UPPER_LIMIT

清算费用:

liquidationFee ≤ PROTOCOL_MAX_LIQUIDATION_FEE

配置信任假设
治理参数:

特权角色(Aave DAO和治理批准的执行者)被视为诚实行为者
配置错误被认为超出审计范围
大多数未明确限制的配置值依赖治理流程而非链上上限
外部协议集成:
Chainlink价格数据源被视为可信
列入白名单的抵押资产被视为可信
这些依赖项行为一致,不会引入任意语义变化

信任边界模型 (Hub ↔ Spoke)
非对称信任架构:

Hub (权威层):

作为唯一的真实来源(single source of truth)
维护全局状态和会计
强制执行不变量
不可变核心
Spoke (执行层):

治理许可: 只有治理明确授权的Spoke才能调用Hub修改器
被视为可信: Spoke在治理审批后被假定为合法运行
职责范围:
决定用户与Hub之间ERC20转账的源/目标地址
控制用户溢价记账的时机
管理Spoke内部的捐赠
在Hub强制的全局不变量下运行
受每个Spoke的上限/标志约束
