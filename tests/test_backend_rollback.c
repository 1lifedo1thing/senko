#include "utun_route.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static int failures;

static void ok(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

#define FAKE_MAX 128

/* a route table that only exists in this process: it records every call in
   order so the test can assert the undo really ran backwards, and it can be
   told to refuse one specific add */
typedef struct {
    struct {
        tun_plan_op_t op;
        uint8_t address[16];
        uint8_t address_len;
        uint8_t prefix;
    } calls[FAKE_MAX];
    size_t call_count;

    /* installed routes, by plan index, so a delete of something that was
       never added can be reported the way the kernel would */
    uint8_t installed[FAKE_MAX];
    size_t installed_count;

    size_t fail_add_at;     /* which add call fails, SIZE_MAX for none */
    size_t add_calls;
    int    fail_errno;
    int    strict_delete;   /* refuse a delete of a route that is not installed */
    char   lookup_ifname[16];
    int    lookup_fails;
} fake_router_t;

static void fake_init(fake_router_t *fake) {
    memset(fake, 0, sizeof *fake);
    fake->fail_add_at = SIZE_MAX;
    fake->fail_errno = EEXIST;
    snprintf(fake->lookup_ifname, sizeof fake->lookup_ifname, "en0");
}

static int fake_find(const fake_router_t *fake, const tun_plan_op_entry_t *op,
                     size_t *out_index) {
    for (size_t i = 0; i < fake->installed_count; ++i) {
        if (!fake->installed[i]) continue;
        if (fake->calls[i].address_len == op->address_len &&
            fake->calls[i].prefix == op->prefix &&
            memcmp(fake->calls[i].address, op->address, op->address_len) == 0) {
            if (out_index) *out_index = i;
            return 1;
        }
    }
    return 0;
}

static int fake_apply(void *ctx, const tun_plan_op_entry_t *op, const char *ifname,
                      utun_route_error_t *out_error) {
    fake_router_t *fake = ctx;
    (void)ifname;
    if (out_error) {
        out_error->code = 0;
        out_error->message[0] = '\0';
    }
    if (fake->call_count >= FAKE_MAX) return -1;

    size_t slot = fake->call_count;
    fake->calls[slot].op = op->op;
    fake->calls[slot].address_len = op->address_len;
    fake->calls[slot].prefix = op->prefix;
    memcpy(fake->calls[slot].address, op->address, op->address_len);
    ++fake->call_count;

    if (op->op == TUN_PLAN_OP_ADD) {
        if (fake->add_calls == fake->fail_add_at) {
            ++fake->add_calls;
            if (out_error) {
                out_error->code = fake->fail_errno;
                snprintf(out_error->message, sizeof out_error->message,
                         "cannot add route %s: a route for this destination already"
                         " exists (errno %d EEXIST)", op->label, fake->fail_errno);
            }
            return -1;
        }
        ++fake->add_calls;
        fake->installed[slot] = 1;
        if (slot + 1 > fake->installed_count) fake->installed_count = slot + 1;
        return 0;
    }

    size_t found = 0;
    if (fake_find(fake, op, &found)) {
        fake->installed[found] = 0;
        return 0;
    }
    if (fake->strict_delete) {
        if (out_error) {
            out_error->code = ESRCH;
            snprintf(out_error->message, sizeof out_error->message,
                     "cannot delete route %s: the kernel has no such route"
                     " (errno %d ESRCH)", op->label, ESRCH);
        }
        return -1;
    }
    return 0;
}

static int fake_lookup(void *ctx, const uint8_t *address, uint8_t address_len,
                       char *ifname_out, size_t ifname_cap,
                       utun_route_error_t *out_error) {
    fake_router_t *fake = ctx;
    (void)address;
    (void)address_len;
    if (out_error) {
        out_error->code = 0;
        out_error->message[0] = '\0';
    }
    if (fake->lookup_fails) {
        if (out_error) {
            out_error->code = ESRCH;
            snprintf(out_error->message, sizeof out_error->message,
                     "the kernel has no route for this address (errno %d ESRCH)",
                     ESRCH);
        }
        return -1;
    }
    snprintf(ifname_out, ifname_cap, "%s", fake->lookup_ifname);
    return 0;
}

static size_t installed_now(const fake_router_t *fake) {
    size_t n = 0;
    for (size_t i = 0; i < fake->installed_count; ++i)
        if (fake->installed[i]) ++n;
    return n;
}

static void build_plan(tun_plan_t *plan, size_t endpoints) {
    tun_plan_input_t input;
    memset(&input, 0, sizeof input);
    snprintf(input.ifname, sizeof input.ifname, "utun4");
    snprintf(input.physical_ifname, sizeof input.physical_ifname, "en0");
    input.have_gateway4 = 1;
    input.gateway4[0] = 192; input.gateway4[1] = 168; input.gateway4[3] = 1;
    for (size_t i = 0; i < endpoints; ++i) {
        input.endpoints[i].address_len = 4;
        input.endpoints[i].address[0] = 203;
        input.endpoints[i].address[2] = 113;
        input.endpoints[i].address[3] = (uint8_t)(i + 1);
    }
    input.endpoint_count = endpoints;
    if (tun_plan_build(&input, plan) != TUN_PLAN_OK) plan->count = 0;
}

int main(void) {
    tun_plan_t plan;
    build_plan(&plan, 2);
    ok("fixture plan built", plan.count == 2 + 2 + 2);

    /* a clean apply installs every operation and leaves nothing to undo */
    fake_router_t fake;
    fake_init(&fake);
    utun_route_executor_t exec = { fake_apply, fake_lookup, &fake };
    utun_route_result_t result;
    ok("clean apply ok", utun_route_apply(&plan, &exec, &result) == UTUN_ROUTE_OK);
    ok("clean apply applied everything", result.applied == plan.count);
    ok("clean apply has no failure", result.failed_index == SIZE_MAX);
    ok("clean apply rolled nothing back", result.rolled_back == 0);
    ok("clean apply left routes installed", installed_now(&fake) == plan.count);

    /* revert removes exactly what apply installed */
    ok("revert ok", utun_route_revert(&plan, &exec, &result) == UTUN_ROUTE_OK);
    ok("revert removed everything", installed_now(&fake) == 0);
    ok("revert counted every undo", result.rolled_back == plan.count);

    /* failure at each step in turn: everything already applied comes back out,
       and nothing stays behind */
    for (size_t step = 0; step < plan.count; ++step) {
        fake_init(&fake);
        fake.fail_add_at = step;
        fake.fail_errno = ENETUNREACH;
        utun_route_executor_t step_exec = { fake_apply, fake_lookup, &fake };
        utun_route_result_t step_result;
        int status = utun_route_apply(&plan, &step_exec, &step_result);
        char name[64];

        snprintf(name, sizeof name, "apply fails at step %zu", step);
        ok(name, status == UTUN_ROUTE_ERR_APPLY);

        snprintf(name, sizeof name, "failed index reported at step %zu", step);
        ok(name, step_result.failed_index == step);

        snprintf(name, sizeof name, "errno reported at step %zu", step);
        ok(name, step_result.failed_errno == ENETUNREACH);

        snprintf(name, sizeof name, "applied count before failure at step %zu", step);
        ok(name, step_result.applied == step);

        snprintf(name, sizeof name, "rollback undid the prefix at step %zu", step);
        ok(name, step_result.rolled_back == step);

        snprintf(name, sizeof name, "no route survives a failure at step %zu", step);
        ok(name, installed_now(&fake) == 0);
    }

    /* ios 5 already has 169.254/16 on en0: the bypass it wanted is in place,
       so apply goes on, and revert leaves the system's route alone */
    size_t bypass = SIZE_MAX, split = SIZE_MAX;
    for (size_t i = 0; i < plan.count; ++i) {
        if (bypass == SIZE_MAX && plan.ops[i].kind == TUN_PLAN_KIND_RESERVED_BYPASS) bypass = i;
        if (split == SIZE_MAX && plan.ops[i].kind == TUN_PLAN_KIND_SPLIT_DEFAULT) split = i;
    }
    ok("fixture has a bypass and a split default", bypass != SIZE_MAX && split != SIZE_MAX);
    fake_init(&fake);
    fake.fail_add_at = bypass;
    fake.strict_delete = 1;
    utun_route_executor_t existing_exec = { fake_apply, fake_lookup, &fake };
    utun_route_result_t existing_result;
    ok("an existing bypass route does not fail the apply",
       utun_route_apply(&plan, &existing_exec, &existing_result) == UTUN_ROUTE_OK &&
       plan.ops[bypass].preexisting);
    ok("the existing bypass route is not counted as ours",
       existing_result.applied == plan.count - 1);
    size_t calls_before = fake.call_count;
    ok("revert succeeds without touching the system's route",
       utun_route_revert(&plan, &existing_exec, &existing_result) == UTUN_ROUTE_OK &&
       existing_result.rolled_back == plan.count - 1 &&
       fake.call_count - calls_before == plan.count - 1 &&
       installed_now(&fake) == 0);

    fake_init(&fake);
    fake.fail_add_at = split;
    utun_route_executor_t taken_exec = { fake_apply, fake_lookup, &fake };
    utun_route_result_t taken_result;
    ok("an existing split default is still an error",
       utun_route_apply(&plan, &taken_exec, &taken_result) == UTUN_ROUTE_ERR_APPLY &&
       taken_result.failed_errno == EEXIST && installed_now(&fake) == 0);

    /* the failure has to reach the caller in words, not only as a number:
       this string is what a log line or the diagnostics screen shows */
    fake_init(&fake);
    fake.fail_add_at = 1;
    utun_route_executor_t message_exec = { fake_apply, fake_lookup, &fake };
    utun_route_result_t message_result;
    utun_route_apply(&plan, &message_exec, &message_result);
    ok("the failure message reaches the caller",
       strstr(message_result.failed_message, "already") != NULL);
    ok("the failure message carries the exact code",
       strstr(message_result.failed_message, "errno") != NULL);
    ok("the failure message names the route",
       strstr(message_result.failed_message, plan.ops[1].label) != NULL);
    ok("a clean rollback leaves no rollback message",
       message_result.rollback_message[0] == '\0');

    /* a refused undo is reported too, with its own reason */
    fake_init(&fake);
    fake.strict_delete = 1;
    utun_route_executor_t undo_exec = { fake_apply, fake_lookup, &fake };
    utun_route_result_t undo_result;
    utun_route_apply(&plan, &undo_exec, &undo_result);
    fake.installed[0] = 0;
    utun_route_revert(&plan, &undo_exec, &undo_result);
    ok("a refused undo is explained",
       strstr(undo_result.rollback_message, "no such route") != NULL);

    /* the undo has to run in reverse: the split defaults must come out before
       the endpoint pin they were installed after */
    fake_init(&fake);
    fake.fail_add_at = plan.count - 1;
    utun_route_executor_t reverse_exec = { fake_apply, fake_lookup, &fake };
    utun_route_result_t reverse_result;
    utun_route_apply(&plan, &reverse_exec, &reverse_result);
    int reverse_order_ok = 1;
    size_t undo_start = plan.count; /* adds occupy call slots 0..count-1 */
    for (size_t i = 0; i < plan.count - 1; ++i) {
        const tun_plan_op_entry_t *expect = &plan.ops[plan.count - 2 - i];
        size_t slot = undo_start + i;
        if (slot >= fake.call_count) { reverse_order_ok = 0; break; }
        if (fake.calls[slot].op != TUN_PLAN_OP_DELETE ||
            fake.calls[slot].address_len != expect->address_len ||
            fake.calls[slot].prefix != expect->prefix ||
            memcmp(fake.calls[slot].address, expect->address, expect->address_len) != 0)
            reverse_order_ok = 0;
    }
    ok("rollback runs in reverse order", reverse_order_ok);

    /* a stale delete, of a route the kernel no longer has, is counted but does
       not stop the rest of the teardown */
    fake_init(&fake);
    fake.strict_delete = 1;
    utun_route_executor_t strict_exec = { fake_apply, fake_lookup, &fake };
    utun_route_result_t strict_result;
    utun_route_apply(&plan, &strict_exec, &strict_result);
    fake.installed[0] = 0; /* something else removed the first route already */
    int revert_status = utun_route_revert(&plan, &strict_exec, &strict_result);
    ok("stale delete is reported", revert_status == UTUN_ROUTE_ERR_APPLY &&
       strict_result.rollback_failures == 1);
    ok("stale delete does not stop the teardown",
       strict_result.rolled_back == plan.count - 1 && installed_now(&fake) == 0);

    /* endpoint verification */
    fake_init(&fake);
    utun_route_executor_t verify_exec = { fake_apply, fake_lookup, &fake };
    size_t failed_index = 0;
    utun_route_error_t verify_error;
    memset(&verify_error, 0, sizeof verify_error);
    ok("verify passes when endpoints leave through the physical interface",
       utun_route_verify_endpoints(&plan, &verify_exec, &failed_index, &verify_error) ==
       UTUN_ROUTE_OK);

    snprintf(fake.lookup_ifname, sizeof fake.lookup_ifname, "utun4");
    ok("verify catches an endpoint routed back into the tunnel",
       utun_route_verify_endpoints(&plan, &verify_exec, &failed_index, &verify_error) ==
       UTUN_ROUTE_ERR_RECURSION);
    ok("a recursion failure is explained",
       strstr(verify_error.message, "routed back into the tunnel") != NULL);
    ok("recursion names the offending operation",
       failed_index < plan.count &&
       plan.ops[failed_index].kind == TUN_PLAN_KIND_ENDPOINT_PIN);

    snprintf(fake.lookup_ifname, sizeof fake.lookup_ifname, "pdp_ip0");
    ok("verify rejects a pin on the wrong physical interface",
       utun_route_verify_endpoints(&plan, &verify_exec, &failed_index, &verify_error) ==
       UTUN_ROUTE_ERR_VERIFY && strstr(verify_error.message, "instead of") != NULL);

    fake_init(&fake);
    fake.lookup_fails = 1;
    utun_route_executor_t missing_exec = { fake_apply, fake_lookup, &fake };
    ok("verify fails when an endpoint has no route at all",
       utun_route_verify_endpoints(&plan, &missing_exec, &failed_index, &verify_error) ==
       UTUN_ROUTE_ERR_VERIFY);
    ok("a failed lookup passes its reason up",
       strstr(verify_error.message, "no route for this address") != NULL &&
       verify_error.code == ESRCH);

    fake_init(&fake);
    snprintf(fake.lookup_ifname, sizeof fake.lookup_ifname, "utun4");
    utun_route_executor_t recursive_exec = { fake_apply, fake_lookup, &fake };
    utun_route_result_t verified_result;
    ok("recursive route apply is rejected",
       utun_route_apply_verified(&plan, &recursive_exec, &verified_result) ==
       UTUN_ROUTE_ERR_RECURSION);
    ok("recursive route apply leaves no routes",
       installed_now(&fake) == 0 && verified_result.rolled_back == plan.count);
    ok("recursive route apply explains the failure",
       strstr(verified_result.failed_message, "routed back") != NULL);

    fake_init(&fake);
    fake.lookup_fails = 1;
    utun_route_executor_t failed_verify_exec = { fake_apply, fake_lookup, &fake };
    ok("failed route lookup rolls back",
       utun_route_apply_verified(&plan, &failed_verify_exec, &verified_result) ==
       UTUN_ROUTE_ERR_VERIFY && installed_now(&fake) == 0 &&
       verified_result.rolled_back == plan.count);

    /* a missing lookup is a programming error, not a silent pass */
    utun_route_executor_t no_lookup = { fake_apply, NULL, &fake };
    ok("verify without a lookup is rejected",
       utun_route_verify_endpoints(&plan, &no_lookup, &failed_index, &verify_error) ==
       UTUN_ROUTE_ERR_ARG);

    route_message_reply_t reply;
    utun_route_path_t physical;
    memset(&reply, 0, sizeof reply);
    snprintf(reply.ifname, sizeof reply.ifname, "pdp_ip0");
    reply.has_interface = 1;
    reply.has_gateway = 1;
    reply.gateway_is_link = 1;
    ok("link-level cellular route has a physical path",
       utun_route_path_from_reply(4, &reply, &physical, &verify_error) == 0 &&
       strcmp(physical.ifname, "pdp_ip0") == 0 && !physical.via_gateway);
    reply.gateway_is_link = 0;
    reply.gateway_len = 4;
    reply.gateway[0] = 192;
    reply.gateway[1] = 0;
    reply.gateway[2] = 2;
    reply.gateway[3] = 1;
    ok("IP gateway is kept for endpoint pins",
       utun_route_path_from_reply(4, &reply, &physical, &verify_error) == 0 &&
       physical.via_gateway && memcmp(physical.gateway, reply.gateway, 4) == 0);
    reply.gateway_len = 16;
    ok("wrong-family gateway is rejected",
       utun_route_path_from_reply(4, &reply, &physical, &verify_error) != 0 &&
       verify_error.code == EAFNOSUPPORT && physical.ifname[0] == '\0');
    reply.has_interface = 0;
    ok("reply without physical interface is rejected",
       utun_route_path_from_reply(4, &reply, &physical, &verify_error) != 0 &&
       verify_error.code == ENXIO);

    /* the system executor must refuse to touch the host's routing table when
       this is built without darwin kernel routing */
#if !defined(__APPLE__)
    const utun_route_executor_t *system_exec = utun_route_system_executor();
    utun_route_result_t system_result;
    ok("system executor refuses on a host build",
       utun_route_apply(&plan, system_exec, &system_result) == UTUN_ROUTE_ERR_APPLY &&
       system_result.applied == 0 && system_result.failed_index == 0);
#endif

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    puts("all backend rollback checks passed");
    return 0;
}
