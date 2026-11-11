// Run with node scripts/test-polkit-rule.mjs. No system policy is modified.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const ruleName = '49-supermgr-operators.rules';
const ruleText = readFileSync(new URL(`../contrib/polkit/${ruleName}`, import.meta.url), 'utf8');
let rule;
vm.runInNewContext(ruleText, {
  polkit: {
    Result: {
      YES: 'yes',
      AUTH_ADMIN_KEEP: 'auth_admin_keep',
    },
    addRule(callback) { rule = callback; },
  },
});
const oncePerSession = ['execute', 'ssh-connect'];
const actions = ['manage', ...oncePerSession, 'secrets', 'tailscale-exit-node', 'tailscale-repair', 'future-action'];
let checks = 0;
for (const id of actions) {
  for (const local of [false, true]) {
    for (const active of [false, true]) {
      for (const operator of [false, true]) {
        const subject = { local, active, isInGroup(group) { return group === 'supermgr' && operator; } };
        let expected = undefined;
        if (local && active && operator) {
          if (id === 'manage') expected = 'yes';
          else if (oncePerSession.includes(id)) expected = 'auth_admin_keep';
        }
        assert.equal(rule({ id: `org.supermgr.daemon.${id}` }, subject),
          expected,
          JSON.stringify({ id, local, active, operator }));
        checks++;
      }
    }
  }
}
const installer = readFileSync(new URL('./install-linux.sh', import.meta.url), 'utf8');
assert.ok(installer.includes(`contrib/polkit/${ruleName}|/usr/share/polkit-1/rules.d/${ruleName}|644`));
console.log(`${checks + 1} policy and installation assertions passed`);
