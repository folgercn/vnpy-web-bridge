## Architecture Impact

- [ ] This PR identifies its Plane:
  - [ ] Research Plane
  - [ ] Control Plane
  - [ ] Execution Plane

- [ ] This PR does not violate Plane boundaries.

## Design

Describe:

- Problem solved
- Design approach
- Why this design matches architecture-v1

## Authority Impact

- [ ] No Authority change
- [ ] New Evidence capability
- [ ] New Acceptance capability
- [ ] New Deployment Authority
- [ ] New Execution Permit capability

Describe any permission changes.

## Security Consideration

Check:

- [ ] Fail Closed
- [ ] No permission bypass
- [ ] No replay vulnerability
- [ ] No unverified external input
- [ ] Evidence integrity maintained

## Execution Impact

- [ ] Does not affect trading execution
- [ ] Affects execution path (requires additional review)

## Test Plan

Include:

- Happy path
- Invalid input
- Failure cases
- Boundary cases

## Risk Assessment

Describe:

- Runtime risk
- Data consistency risk
- Production impact

## LLM Development Compliance

If AI assisted:

- [ ] Architecture Impact reviewed
- [ ] Existing contracts checked before adding new schemas
- [ ] No shortcut implementation bypasses security boundaries

## Frontend Review（涉及 `frontend/` 时）

- [ ] 复用了共享组件，Naive UI 组件均显式局部 import
- [ ] 按钮主次、warning/destructive 语义一致
- [ ] 桌面、平板、手机和暗色模式已验证
- [ ] RBAC、loading、error、empty、disabled 状态完整
- [ ] `npm run check` 已通过
