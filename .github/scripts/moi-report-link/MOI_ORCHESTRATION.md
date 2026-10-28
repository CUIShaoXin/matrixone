# MOI 统一调度接入（Issue #18820）

## 当前交付范围

本任务后续开发目录为 `/Users/cuishaoxin/matrixflow/matrixflow-git`。
编排代码、原有执行依赖和测试统一位于 `.github/scripts/moi-report-link/`，
新手动/API入口位于 `.github/workflows/moi-managed-security.yml`。
本地测试不依赖原来的独立工作树；不在该目录内创建嵌套 Git 仓库。

执行程序以生产版本 `e3a7b76c4953965709019cd3eff6ad2780a7b4d4` 为基线。
现有生产定时仍位于 `CUIShaoXin/matrixone` 的 `moi-daily-cloud-acceptance.yml`。
该定时没有迁入当前仓库的活动 workflow，避免出现额外定时入口；
原文件的只读取证副本位于 `output/security-orchestration-18820/production-workflow-reference.yml`。
新增入口仅接受手动/API触发，没有新增定时。
扫描、Kimi 代码/API 审查、报告生成及企业微信发送函数继续由原实现负责。

新增入口 `managed_entry.py` 顺序执行原 `daily_pipeline.main`，仅成功后进入原投递校验。
`no_send` 对本批报告运行真实 `check_bundle` 和消息构造，既不创建生产 ready 指针，也不申请发送 claim。
`production` 仍遵守北京时间10点投递门禁，并复用原当日全局 claim、原始任务回读和发送回执。

## 调用参数

| workflow input | 含义 |
| --- | --- |
| `mode=managed` | 采集、扫描、审查、报告和投递校验全流程 |
| `mode=status-sync` | 仅将已保存状态补写MOI；不执行扫描、审查或发送 |
| `mode=status-reconcile` | 查询原GitHub run/attempt的真实终态，保存证据并补写MOI；不执行业务流程 |
| `mode=regressions` | 独立job仅运行本地协议和恢复回归；不读取生产secrets、不创建业务批次、不占生产扫描并发组 |
| `runtime_ref` | 包含本次代码且已验证的40位提交SHA，必须显式提供 |
| `run_id` | MOI创建的业务批次；所有重试保留此值 |
| `business_date` | Asia/Shanghai业务日期，YYYY-MM-DD；跨午夜恢复沿用原日期 |
| `trigger_source` | github_manual / moi_manual / moi_api / moi_schedule；GitHub 页面验收默认 github_manual |
| `execution_mode` | no_send（默认）或production |

生产补发仅允许当天，不允许将历史日报伪装成当日通知。已确认成功仍受原共享发送记录约束。
同批次不允许切换 no_send/production；新建测试批次不占用生产日报 ready 指针。

`moi_actions.dispatch(actions, objects, context, runtime_sha, workflow_ref)` 是供调度 owner 调用的适配函数。
调用方必须提供自己的受管 GitHub 身份及检查点存储，不从其他owner复制凭据。
`workflow_ref` 必须显式指定：开发入口使用 `moi-orchestration-18820`，未来正式发布后才使用 `main`。
它与固定的 `runtime_sha`、业务日期、触发来源和执行模式共同进入本批请求摘要；
同批次更换入口分支或执行提交会在请求 GitHub 前返回 `dispatch_batch_request_conflict`。
它先用原条件PUT记录请求，再调用真正的GitHub workflow_dispatch，返回 submitted/unknown/rejected，
只有读取真实workflow run后才关联GitHub ID、attempt、实际status和conclusion。
POST超时或进程中断后的同批次调用只查询，不盲目重新POST。
首次关联查询读取该workflow最新100个dispatch记录；未找到时保持等待/未知，禁止当作成功或自动重发。
已有GitHub关联后直接查询原run，后续重跑更新真实attempt，不再依赖最近100条列表。
状态补写与终态核验使用独立运行标题，避免与完整执行的run_id关联产生歧义。
dispatch 请求记录的后续更新使用 MinIO ETag 条件写入。较晚返回的 POST 响应不能擦除
其他观察者已经关联的 GitHub run；旧轮询不能覆盖新 attempt，或将同 attempt 的 completed 改回运行中。
同 attempt 出现矛盾终态、并发关联到不同 run、缺少 ETag 或持续写冲突时显式返回错误，保留已有证据。
存储确认丢失后的恢复只读取原意图与真实 GitHub 运行，不重新 POST；403 保留 rejected，504 保留 unknown。
这里的防重复覆盖 dispatch 请求，不代替原日报发送 claim 与回执校验。

## 供原生运行 owner 接入的控制入口

`moi_control.Controller` 提供 `prepare/start/status/resume/sync`，命令行同名文件提供
`prepare/start/status/resume/status-sync/status-reconcile`。调用方必须从真实已持久化的 MOI
运行上下文注入 `owner_run_id`，并使用该 owner 的受管 GitHub 和工作区身份。
本模块不验证原生运行资源的授权，不是对外鉴权接口；不能把任意用户输入的字符串当成可信运行身份。
没有 `MOI_API_KEY` 时CLI返回 `missing_moi_api_key`，不会提交 GitHub 请求。
本机原有 `gh` 登录可用于调用方的 GitHub 请求，但不会解决 MOI 工作区连接缺失。

创建顺序为：条件保存 owner 请求及冻结的日期/业务身份，条件保存批次，回读两者，再保存 dispatch 意图并请求 GitHub。
owner请求位置为 `receipts/moi/owner-runs/<owner ID SHA-256>.json`。
批次索引为 `receipts/YYYYMMDD/moi-batches/production.json`，测试批次用owner哈希替代 `production`。
缺省日期是 Asia/Shanghai 当日；没有设置默认T-1。跨午夜重试或首次保存响应丢失后恢复，继续使用最初冻结的日期。
同日生产入口复用 `daily-YYYYMMDD`；不同owner的no_send为独立测试批次。
同owner更换日期、模式、执行提交或入口分支会拒绝；多来源命中同生产批次保留最初来源。
如发现原生产批次已有检查点但没有受管 dispatch 关联，返回 `existing_batch_requires_reconciliation`，不启动另一执行。

`status`观察原GitHub运行并读取阶段快照；查询缺失批次不会创建批次或提交执行。
`resume`要求显式传入已批准的 `max_retries`，在原GitHub run上重跑并取得真实的新attempt。
每次重跑先条件保存 `orchestration/retries/<GitHub run>-<原attempt>.json`；超时或未知结果不重复提交。
运行中只查询；业务已成功或发送已确认时返回 `status_sync_required`，仅允许独立状态补写。
尚未实现自动重试计划或退避定时，不能把手动恢复入口当成已启用后台重试。

该入口已具备本地协议测试，仍需部署到现有 MOI 自动化/工作流 owner，并完成可信身份注入、
原生运行详情投影、后台终态轮询及工具绑定。保存本地代码或发布到 GitHub 不会自动在 MOI 页面创建智能体工具。
不为此次编排新建平行调度器，也不把原执行链路的凭据复制到新的owner。

## MOI 原生调用入口

本地 MOI 已有 `agentresource` 自动化任务、运行记录与 Workflow/Mowl 调度 owner；
任务修改时间、启停、手动及 API 触发应沿用这些入口，不新增安全日报专用 cron 或调度器。
已有 `moi_github_actions_control` 通过绑定的 GitHub channel 和原 `moi:github.repo.write`
WorkItem 发起真实 dispatch。底层 Worker 和 Catalog 发布的工具合同均已支持 `inputs`；
本次仅补齐另一份原生运行时定义，保持合同一致。
公共目录的旧实现测试通过，不能将此改动解释为修复了正式 Catalog 调用链的参数拦截。
原生工具可表达的业务参数为：

```json
{
  "operation": "dispatch_workflow",
  "workflow_id": "moi-managed-security.yml",
  "ref": "moi-orchestration-18820",
  "inputs": {
    "mode": "managed",
    "run_id": "moi-security-20261027-18820",
    "business_date": "2026-10-27",
    "trigger_source": "moi_api",
    "execution_mode": "no_send",
    "runtime_ref": "116871b53267c4a047790ef96a121d7d21ff51dc"
  }
}
```

上例只展示测试参数合同，不应自动执行或复用为生产批次。
`ref` 选择触发入口的 Git 分支；`inputs.runtime_ref` 冻结真正执行的代码提交。
`inputs.run_id` 是业务批次，Actions 查询、重跑与取消的顶层数字 `run_id` 是 GitHub 运行标识。
二者不能互换。凭据仍由原受管 channel 提供，不写入 `inputs`、提示词或公开 Workflow DSL；
原仓库范围校验继续拒绝 owner/repo/host 越界，原生成权限边界及运行期准入沿用现有实现。
接受 dispatch 只表示请求已提交，不表示三仓扫描、报告或发送已经完成。

该改动只对齐原生工具合同，尚未把安全日报的持久化 dispatch、状态收敛和回执接入 MOI 自动化运行 owner。
调度接入必须继续使用同一批次的请求记录、真实 Actions 关联与结果回读；
不能将一次工具返回或新增任务记录当作整条链路完成。受限凭据继续按用户要求暂时跳过。

## 状态与失败恢复

MinIO根前缀：`receipts/YYYYMMDD/pipeline-RUN_ID/`。
原逐仓固定SHA检查点：`receipts/YYYYMMDD/acquisition-RUN_ID/REPO.json`。
新增逐仓version/download/validation/storage阶段状态、失败类型/安全code及采集尝试记录。
原root保存本批每次GitHub执行关联；恢复前重新核验已保存ZIP对象。

ZIP采集仍按matrixone、taas、matrixflow顺序执行；三仓对象全部校验通过后，外层用三个工作线程
并行调用原组件扫描函数。原代码/API审查保持已有并发方式。
各仓独立检查点和失败原因保留，等待全部扫描返回后按固定仓库顺序汇总；任一仓失败仍阻止完整报告。
此次仅改变外层组件调用调度，原扫描、审查、报告、发送函数保持原实现。
API/端口审查基于源码，不代表已执行动态接口测试或网络端口探测。

`component_recovery.ComponentRunner` 在原 `Runner` 外增加失败产物恢复，原扫描函数保持不变。
仅当原校验返回 `employee_marker_missing`、对应 finalize 已 completed，且产物缓存哈希仍一致时，
才为相同输入分配新的 finalize workflow ID。原 parse、OSV query/advisory、已成功仓库和代码/API审查继续复用原检查点。
节点、提示词、token参数、扫描操作符、报告和投递校验保持原合同；不补造marker。
同批次最多三个 finalize 尝试（含原尝试），重启不重置预算；每次尝试的身份先持久化，再执行远端调用。
提交结果未知、输入变化、缓存损坏及其他失败不会自动启动新尝试。
原失败产物、workflow状态和失败原因保留；快照增加逐仓 `component_attempts`、`component_retry_count` 和当前扫描失败字段。
已开始但内容仍为空的仓库检查点显示running，尚未创建检查点的仓库显示waiting。

状态快照：`orchestration/status.json`，包含批次、真实GitHub运行、逐仓版本、ZIP大小/哈希/位置、
采集阶段、扫描/审查状态、失败、重试关联、报告链接及发送回执file_id。
运行中约每60秒读取现有检查点并上传MOI Catalog状态文件，结束后再次同步并逐字回读。
每个快照文件名携带同一run_id及内容哈希；这提供可追溯文件，尚不等于MOI页面中的统一运行详情卡片。

MOI不可用时快照先保存MinIO，最终结果显式标记replay_required。
`status-sync`调用`orchestration_status.upload_saved`；报告详情读取曾失败时，先回读原报告回执补齐链接，再回传状态，绝不重新扫描或发送。
ZIP本地缓存也按业务日期与run_id隔离，不跨业务批次复用下载缓存。
发送结果未知时状态保留null，不转写成确认未发送。
状态同步的超时仍可能留下MOI文件但丢失上传回执；重放可能产生同内容状态文件，不能据此声称文件上传exactly-once。
`moi_actions.reconcile(actions, api, objects, context)` 供MOI调度owner查询已绑定的真实Actions attempt。
它校验仓库、workflow、触发事件、批次标题、run和attempt，并将completed证据按run/attempt条件创建到
`orchestration/actions/GITHUB_RUN_ID/ATTEMPT.json`。尚未写出首个快照时使用原dispatch绑定，
不会把MOI调用方或状态核验job的GitHub身份写成本次业务执行身份。
终态投影保留已确认的扫描结果、报告、失败记录和发送回执；中断时仍在运行的阶段标记unknown，
生产发送缺少确认时保留null。GitHub success不能将缺失的业务完成记录补造成成功。
共享状态更新使用MinIO ETag条件写入，冲突后重新读取当前快照；旧attempt证据不能覆盖新attempt。
新重试已登记而首个心跳尚未写出时，按原root的executions顺序推进旧快照，重新读取已验收检查点；
`previous_execution`保留前一次运行结果。快照身份不在较旧journal中时不回退它，已确认发送的回执继续保留。
MOI或报告读取失败时先保留终态，恢复后可单独重放；重放不会启动扫描或企业微信发送。
`status-reconcile` 使用当前job只读`actions: read`权限及临时GitHub token，不需要新增个人令牌。
该入口目前是可调用的核验能力；MOI调度owner仍需接入它，不能宣称已部署自动终态轮询。

## 验证与尚未完成的验收

本地入口集成场景使用真实ZIP字节、CRC/提交校验和对象哈希回读；网络边界用内存存储隔离。
同一场景运行原daily_pipeline时失败：批次变成GitHub ID、日期变成runner当天；修复后按MOI身份通过。
现有扫描、恢复、投递、生命周期测试与新增编排测试全部运行，具体结果以交付记录为准。
dispatch 并发恢复场景使用本地真实 HTTP 服务及遵守条件 PUT/ETag 的对象存储夹具；
原实现已复现运行关联丢失、attempt 回退和终态覆盖，修复后验证并发、异常与恢复行为。
MOI 公共工具目录通过真实服务和 Product SDK 的 API Key、Token 两种身份验证；
Worker 的 dispatch 参数通过真实 HTTP 协议回归。这些验证均不等于 MOI 发起了真实云端扫描。

工作目录为当前仓库的 `.github/scripts/moi-report-link/`，执行：

```sh
python3 -m unittest discover -p 'test_*.py'
```

本次迁入清单、代码哈希、独立补丁、测试日志和发布状态统一保存在
`output/security-orchestration-18820/`。该目录不保存令牌、私钥、私有配置、完整ZIP或报告预签名URL。
原扫描与报告依赖随迁入保持原字节；编排增量与基线差异由 `runtime.patch` 记录。

2026-10-27，新增入口和执行版本 `6d1f4f6351f88c373dbba8e96461e4ab6f17452b`
已发布到 `CUIShaoXin/matrixone`。真实云端不发送批次
`moi-validation-20261027-18820`（GitHub run `40471569071`）已运行并以 failure 结束。
三仓ZIP固定版本采集成功，期间状态已回传MOI并回读一致；
taas组件产物被原校验以 `employee_marker_missing` 拒绝，因此未通过完整报告和投递验收。
后续本地已实现上述恢复及回归覆盖；该历史失败运行仍保留原结论，新版本尚需真实云端补验。

恢复补丁已发布到开发分支 `moi-orchestration-18820`，执行提交为
`a793c559ed1e0f3549e0dd025f1d76421aeb9365`。原业务批次的云端恢复运行是
`40507205377`，来源为github_manual，模式为no_send；它不代表MOI入口已经接通。
本地执行器完整测试134项通过，新增入口回归先证明旧路径失败，再验证恢复、预算上限、重启、未知提交、缓存损坏和输入变化。
2026-10-27 21:19（Asia/Shanghai），恢复运行已完成，GitHub结论为success。
三仓组件、代码及API／端口审查均accepted，报告已发布，no_send投递校验通过；没有发送群消息。
最终MOI快照file_id为`c710d03d-99cb-42b6-8f27-513af3e0d41a`，独立回读与MinIO原始字节一致。
这完成了GitHub手动入口的真实云端no_send恢复验收，尚不代表MOI触发、调度及测试群发送验收。
新增终态回传的本地完整测试150项通过。执行代码已发布到开发分支，最新提交为
`116871b53267c4a047790ef96a121d7d21ff51dc`；初版只读核验run `40513448413`成功。
后续注册重试边界的只读核验run `40514618719`也已success，业务执行步骤明确skipped。
MOI回读file_id为`61fd72ce-c0c7-4d49-9b83-6a427139d89c`，与MinIO快照逐字一致：
最新业务执行为cancelled，previous_execution保留原success，三仓采集／扫描／审查和报告仍为succeeded，sent=false。
完整记录见`actions-terminal-validation.json`与`actions-terminal-cloud-status.json`。
浏览器选择模式时曾误提交同批次no_send重试`40512966211`，该run已取消；
取消生效前它进入了原已发布批次的恢复校验。原成功run `40507205377`、已验收报告及失败历史保持可追溯。
证据及后续状态以 `output/security-orchestration-18820/component-recovery-validation.json`
和 `recovery-cloud-progress.json` 为准。

MOI连接按用户选择限定为 `CUIShaoXin/matrixone`；用户已选择暂时跳过受限凭据接入，继续开发。
新GitHub CLI宽范围连接已在MOI卸载并断开；这不等于撤销GitHub服务端已有OAuth授权。

以下尚未完成，不应标记整条链路验收通过：

1. 在MOI当前部署的调度owner接入受管GitHub授权、上述dispatch适配及回传结果。
   当前仅有可调用Python适配，不存在已部署的MOI触发API或自动化任务。
   不能将token写入公开workflow DSL、agent提示词或状态快照来替代受管授权。
2. 在MOI同一运行记录关联进度、报告与回执，接入终态核验及心跳检测；文件归档不能冒充该页面能力。
3. 实测新版任务时间修改、暂停与恢复；保留现有两条旧任务状态，不能把开关它们当作接入。
4. 实测MOI跨入口重复触发和真实测试群回执；本批已完成GitHub入口失败恢复、状态补写与取消回传。
5. 排定切换业务日期，停GitHub独立schedule并启MOI唯一定时入口，然后验证连续3个日历日。

切换前不关闭现有GitHub生产schedule；回滚保留原workflow和人工恢复参数。
