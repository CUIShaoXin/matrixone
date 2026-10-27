# MOI 统一调度接入（Issue #18820）

## 当前交付范围

本分支以当前生产执行版本 `e3a7b76c4953965709019cd3eff6ad2780a7b4d4` 为基线。
原 `moi-daily-cloud-acceptance.yml` 保持逐字不变，新入口为仅手动/API触发的 `moi-managed-security.yml`，没有新增定时。
扫描、Kimi 代码/API 审查、报告生成及企业微信发送函数继续由原实现负责。

新增入口 `managed_entry.py` 顺序执行原 `daily_pipeline.main`，仅成功后进入原投递校验。
`no_send` 对本批报告运行真实 `check_bundle` 和消息构造，既不创建生产 ready 指针，也不申请发送 claim。
`production` 仍遵守北京时间10点投递门禁，并复用原当日全局 claim、原始任务回读和发送回执。

## 调用参数

| workflow input | 含义 |
| --- | --- |
| `mode=managed` | 采集、扫描、审查、报告和投递校验全流程 |
| `mode=status-sync` | 仅将已保存状态补写MOI；不执行扫描、审查或发送 |
| `runtime_ref` | 包含本次代码且已验证的40位提交SHA，必须显式提供 |
| `run_id` | MOI创建的业务批次；所有重试保留此值 |
| `business_date` | Asia/Shanghai业务日期，YYYY-MM-DD；跨午夜恢复沿用原日期 |
| `trigger_source` | moi_manual / moi_api / moi_schedule |
| `execution_mode` | no_send（默认）或production |

生产补发仅允许当天，不允许将历史日报伪装成当日通知。已确认成功仍受原共享发送记录约束。
同批次不允许切换 no_send/production；新建测试批次不占用生产日报 ready 指针。

`moi_actions.dispatch(actions, objects, context, runtime_sha)` 是供调度 owner 调用的适配函数。
调用方必须提供自己的受管 GitHub 身份及检查点存储，不从其他owner复制凭据。
它先用原条件PUT记录请求，再调用真正的GitHub workflow_dispatch，返回 submitted/unknown/rejected，
只有读取真实workflow run后才关联GitHub ID、attempt、实际status和conclusion。
POST超时或进程中断后的同批次调用只查询，不盲目重新POST。
当前关联查询读取该workflow最新100个dispatch记录；未找到时保持等待/未知，禁止当作成功或自动重发。

## 状态与失败恢复

MinIO根前缀：`receipts/YYYYMMDD/pipeline-RUN_ID/`。
原逐仓固定SHA检查点：`receipts/YYYYMMDD/acquisition-RUN_ID/REPO.json`。
新增逐仓version/download/validation/storage阶段状态、失败类型/安全code及采集尝试记录。
原root保存本批每次GitHub执行关联；恢复前重新核验已保存ZIP对象。

状态快照：`orchestration/status.json`，包含批次、真实GitHub运行、逐仓版本、ZIP大小/哈希/位置、
采集阶段、扫描/审查状态、失败、重试关联、报告链接及发送回执file_id。
运行中约每60秒读取现有检查点并上传MOI Catalog状态文件，结束后再次同步并逐字回读。
每个快照文件名携带同一run_id及内容哈希；这提供可追溯文件，尚不等于MOI页面中的统一运行详情卡片。

MOI不可用时快照先保存MinIO，最终结果显式标记replay_required。
`status-sync`调用`orchestration_status.upload_saved`；报告详情读取曾失败时，先回读原报告回执补齐链接，再回传状态，绝不重新扫描或发送。
ZIP本地缓存也按业务日期与run_id隔离，不跨业务批次复用下载缓存。
发送结果未知时状态保留null，不转写成确认未发送。
状态同步的超时仍可能留下MOI文件但丢失上传回执；重放可能产生同内容状态文件，不能据此声称文件上传exactly-once。
GitHub取消/runner中断仍需由MOI调度owner根据真实Actions终态收敛，不能仅依赖最后一次running快照。

## 验证与尚未完成的验收

本地入口集成场景使用真实ZIP字节、CRC/提交校验和对象哈希回读；网络边界用内存存储隔离。
同一场景运行原daily_pipeline时失败：批次变成GitHub ID、日期变成runner当天；修复后按MOI身份通过。
现有扫描、恢复、投递、生命周期测试与新增编排测试全部运行，具体结果以交付记录为准。

以下尚未完成，不应标记整条链路验收通过：

1. 将新增workflow和runtime发布到GitHub并执行真实no_send全链路。
2. 在MOI当前部署的调度owner接入受管GitHub授权、上述dispatch适配及回传结果。
   当前仅有可调用Python适配，不存在已部署的MOI触发API或自动化任务。
   不能将token写入公开workflow DSL、agent提示词或状态快照来替代受管授权。
3. 在MOI同一运行记录关联进度、报告与回执，增加终态/心跳超时收敛；文件归档不能冒充该页面能力。
4. 实测新版任务时间修改、暂停与恢复；保留现有两条旧任务状态，不能把开关它们当作接入。
5. 实测跨入口重复触发、失败恢复、状态补写和真实测试群回执。
6. 排定切换业务日期，停GitHub独立schedule并启MOI唯一定时入口，然后验证连续3个日历日。

切换前不关闭现有GitHub生产schedule；回滚保留原workflow和人工恢复参数。
