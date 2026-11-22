## 变更说明

<!-- 这个 PR 做了什么？为什么需要？关联的动机或设计取舍写在这里。 -->

## 关联 Issue

<!-- 例如：Closes #123（没有就写“无”） -->

## 变更类型

- [ ] Bug 修复
- [ ] 新功能
- [ ] 重构 / 性能优化
- [ ] 文档 / 构建 / CI

## 自查清单

- [ ] `python -m pytest -q` 全部通过
- [ ] `python -m pyflakes app launcher.py tests` 无输出（干净）
- [ ] `python -m compileall -q app tests launcher.py` 通过
- [ ] 测试仍然全部离线，没有引入真实外网请求
- [ ] 行为有变化时已同步更新 `README.md` / `CHANGELOG.md`
- [ ] 新增/修改的逻辑已附带或更新测试
- [ ] **没有**提交任何密钥、`.env`、token、扫描结果（`res/`）或调试日志
- [ ] 改动遵循 AGPL-3.0 许可

## 合规声明

- [ ] 本 PR 不改动工具“仅用于已授权目标”的定位，且不附带任何真实目标数据
