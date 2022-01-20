package scot.massie.lib.permissions.decorators;

import org.junit.jupiter.api.Test;
import scot.massie.lib.permissions.GroupMapPermissionsRegistry;
import scot.massie.lib.permissions.GroupMapPermissionsRegistryTest;
import scot.massie.lib.permissions.PermissionsRegistryTest;
import scot.massie.lib.permissions.events.PermissionsChangedEventTarget;
import scot.massie.lib.utils.wrappers.MutableWrapper;

import static org.assertj.core.api.Assertions.*;

public class PermissionsRegistryWithEventsTest extends PermissionsRegistryTest<PermissionsRegistryWithEvents<String>>
{
    @Override
    protected PermissionsRegistryWithEvents<String> getNewPermissionsRegistry()
    { return new PermissionsRegistryWithEvents<>(s -> s, s -> s); }

    @Override
    protected void createUser(PermissionsRegistryWithEvents<String> reg, String userId)
    {
        // TO DO: Write.
        throw new UnsupportedOperationException("Not yet implemented.");
    }

    @Override
    protected void createGroup(PermissionsRegistryWithEvents<String> reg, String groupName)
    {
        // TO DO: Write.
        throw new UnsupportedOperationException("Not yet implemented.");
    }

    @Override
    protected void createGroup(PermissionsRegistryWithEvents<String> reg, String groupName, int priority)
    {
        // TO DO: Write.
        throw new UnsupportedOperationException("Not yet implemented.");
    }

    @Override
    protected void createGroup(PermissionsRegistryWithEvents<String> reg, String groupName, double priority)
    {
        // TO DO: Write.
        throw new UnsupportedOperationException("Not yet implemented.");
    }

    @Test
    void events_assignUserPermission()
    {
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistry();
        MutableWrapper<Boolean> happened = new MutableWrapper<>(false);

        reg.permissionAssigned.register(args ->
        {
            happened.set(true);

            assertThat(args.getTarget()).isSameAs(PermissionsChangedEventTarget.USER);
            assertThat(args.getUserTargeted()).isEqualTo("doot");
            assertThat(args.getGroupTargetedId()).isNull();
            assertThat(args.getPermission()).isEqualTo("first.second:someArg");
        });

        reg.assignUserPermission("doot", "first.second:someArg");
        assertThat(happened.get()).withFailMessage("Event didn't fire.").isTrue();
    }

    @Test
    void events_assignGroupPermission()
    {
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistry();
        MutableWrapper<Boolean> happened = new MutableWrapper<>(false);

        reg.permissionAssigned.register(args ->
        {
            happened.set(true);

            assertThat(args.getTarget()).isSameAs(PermissionsChangedEventTarget.GROUP);
            assertThat(args.getUserTargeted()).isNull();
            assertThat(args.getGroupTargetedId()).isEqualTo("doot");
            assertThat(args.getPermission()).isEqualTo("first.second:someArg");
        });

        reg.assignGroupPermission("doot", "first.second:someArg");
        assertThat(happened.get()).withFailMessage("Event didn't fire.").isTrue();
    }

    @Test
    void events_assignDefaultPermission()
    {
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistry();
        MutableWrapper<Boolean> happened = new MutableWrapper<>(false);

        reg.permissionAssigned.register(args ->
        {
            happened.set(true);

            assertThat(args.getTarget()).isSameAs(PermissionsChangedEventTarget.DEFAULT_PERMISSIONS);
            assertThat(args.getUserTargeted()).isNull();
            assertThat(args.getGroupTargetedId()).isNull();
            assertThat(args.getPermission()).isEqualTo("first.second:someArg");
        });

        reg.assignDefaultPermission("first.second:someArg");
        assertThat(happened.get()).withFailMessage("Event didn't fire.").isTrue();
    }

    @Test
    void events_revokeUserPermission_permissionPresent()
    {
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistry();
        MutableWrapper<Boolean> happened = new MutableWrapper<>(false);
        reg.assignUserPermission("doot", "first.second:someArg");

        reg.permissionRevoked.register(args ->
        {
            happened.set(true);

            assertThat(args.getTarget()).isSameAs(PermissionsChangedEventTarget.USER);
            assertThat(args.getUserTargeted()).isEqualTo("doot");
            assertThat(args.getGroupTargetedId()).isNull();
            assertThat(args.getPermission()).isEqualTo("first.second");
        });

        reg.revokeUserPermission("doot", "first.second");
        assertThat(happened.get()).withFailMessage("Event didn't fire.").isTrue();
    }

    @Test
    void events_revokeUserPermission_permissionNotPresent()
    {
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistry();
        MutableWrapper<Boolean> happened = new MutableWrapper<>(false);

        reg.permissionRevoked.register(args ->
        {
            happened.set(true);

            assertThat(args.getTarget()).isSameAs(PermissionsChangedEventTarget.USER);
            assertThat(args.getUserTargeted()).isEqualTo("doot");
            assertThat(args.getGroupTargetedId()).isNull();
            assertThat(args.getPermission()).isEqualTo("first.second");
        });

        reg.revokeUserPermission("doot", "first.second");
        assertThat(happened.get()).withFailMessage("Event didn't fire.").isTrue();
    }

    @Test
    void events_revokeGroupPermission_permissionPresent()
    {
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistry();
        MutableWrapper<Boolean> happened = new MutableWrapper<>(false);
        reg.assignGroupPermission("doot", "first.second:someArg");

        reg.permissionRevoked.register(args ->
        {
            happened.set(true);

            assertThat(args.getTarget()).isSameAs(PermissionsChangedEventTarget.GROUP);
            assertThat(args.getUserTargeted()).isNull();
            assertThat(args.getGroupTargetedId()).isEqualTo("doot");
            assertThat(args.getPermission()).isEqualTo("first.second");
        });

        reg.revokeGroupPermission("doot", "first.second");
        assertThat(happened.get()).withFailMessage("Event didn't fire.").isTrue();
    }

    @Test
    void events_revokeGroupPermission_permissionNotPresent()
    {
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistry();
        MutableWrapper<Boolean> happened = new MutableWrapper<>(false);

        reg.permissionRevoked.register(args ->
        {
            happened.set(true);

            assertThat(args.getTarget()).isSameAs(PermissionsChangedEventTarget.GROUP);
            assertThat(args.getUserTargeted()).isNull();
            assertThat(args.getGroupTargetedId()).isEqualTo("doot");
            assertThat(args.getPermission()).isEqualTo("first.second");
        });

        reg.revokeGroupPermission("doot", "first.second");
        assertThat(happened.get()).withFailMessage("Event didn't fire.").isTrue();
    }

    @Test
    void events_revokeDefaultPermission_permissionPresent()
    {
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistry();
        MutableWrapper<Boolean> happened = new MutableWrapper<>(false);
        reg.assignDefaultPermission("first.second:someArg");

        reg.permissionRevoked.register(args ->
        {
            happened.set(true);

            assertThat(args.getTarget()).isSameAs(PermissionsChangedEventTarget.DEFAULT_PERMISSIONS);
            assertThat(args.getUserTargeted()).isNull();
            assertThat(args.getGroupTargetedId()).isNull();
            assertThat(args.getPermission()).isEqualTo("first.second");
        });

        reg.revokeDefaultPermission("first.second");
        assertThat(happened.get()).withFailMessage("Event didn't fire.").isTrue();
    }

    @Test
    void events_revokeDefaultPermission_permissionNotPresent()
    {
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistry();
        MutableWrapper<Boolean> happened = new MutableWrapper<>(false);

        reg.permissionRevoked.register(args ->
        {
            happened.set(true);

            assertThat(args.getTarget()).isSameAs(PermissionsChangedEventTarget.DEFAULT_PERMISSIONS);
            assertThat(args.getUserTargeted()).isNull();
            assertThat(args.getGroupTargetedId()).isNull();
            assertThat(args.getPermission()).isEqualTo("first.second");
        });

        reg.revokeDefaultPermission("first.second");
        assertThat(happened.get()).withFailMessage("Event didn't fire.").isTrue();
    }

    @Test
    void events_assignGroupToUser()
    {
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistry();
        MutableWrapper<Boolean> happened = new MutableWrapper<>(false);

        reg.groupAssigned.register(args ->
        {
            happened.set(true);

            assertThat(args.getTarget()).isSameAs(PermissionsChangedEventTarget.USER);
            assertThat(args.getUserTargeted()).isEqualTo("doottarget");
            assertThat(args.getGroupTargetedId()).isNull();
            assertThat(args.getGroupAssociatedId()).isEqualTo("dootgroup");
        });

        reg.assignGroupToUser("doottarget", "dootgroup");
        assertThat(happened.get()).withFailMessage("Event didn't fire.").isTrue();
    }

    @Test
    void events_assignGroupToGroup()
    {
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistry();
        MutableWrapper<Boolean> happened = new MutableWrapper<>(false);

        reg.groupAssigned.register(args ->
        {
            happened.set(true);

            assertThat(args.getTarget()).isSameAs(PermissionsChangedEventTarget.GROUP);
            assertThat(args.getUserTargeted()).isNull();
            assertThat(args.getGroupTargetedId()).isEqualTo("doottarget");
            assertThat(args.getGroupAssociatedId()).isEqualTo("dootgroup");
        });

        reg.assignGroupToGroup("doottarget", "dootgroup");
        assertThat(happened.get()).withFailMessage("Event didn't fire.").isTrue();
    }

    @Test
    void events_assignDefaultGroup()
    {
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistry();
        MutableWrapper<Boolean> happened = new MutableWrapper<>(false);

        reg.groupAssigned.register(args ->
        {
            happened.set(true);

            assertThat(args.getTarget()).isSameAs(PermissionsChangedEventTarget.DEFAULT_PERMISSIONS);
            assertThat(args.getUserTargeted()).isNull();
            assertThat(args.getGroupTargetedId()).isNull();
            assertThat(args.getGroupAssociatedId()).isEqualTo("dootgroup");
        });

        reg.assignDefaultGroup("dootgroup");
        assertThat(happened.get()).withFailMessage("Event didn't fire.").isTrue();
    }

    @Test
    void events_revokeGroupFromUser_groupPresent()
    {
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistry();
        MutableWrapper<Boolean> happened = new MutableWrapper<>(false);
        reg.assignGroupToUser("doottarget", "dootgroup");

        reg.groupRevoked.register(args ->
        {
            happened.set(true);

            assertThat(args.getTarget()).isSameAs(PermissionsChangedEventTarget.USER);
            assertThat(args.getUserTargeted()).isEqualTo("doottarget");
            assertThat(args.getGroupTargetedId()).isNull();
            assertThat(args.getGroupAssociatedId()).isEqualTo("dootgroup");
        });

        reg.revokeGroupFromUser("doottarget", "dootgroup");
        assertThat(happened.get()).withFailMessage("Event didn't fire.").isTrue();
    }

    @Test
    void events_revokeGroupFromUser_groupNotPresent()
    {
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistry();
        MutableWrapper<Boolean> happened = new MutableWrapper<>(false);

        reg.groupRevoked.register(args ->
        {
            happened.set(true);

            assertThat(args.getTarget()).isSameAs(PermissionsChangedEventTarget.USER);
            assertThat(args.getUserTargeted()).isEqualTo("doottarget");
            assertThat(args.getGroupTargetedId()).isNull();
            assertThat(args.getGroupAssociatedId()).isEqualTo("dootgroup");
        });

        reg.revokeGroupFromUser("doottarget", "dootgroup");
        assertThat(happened.get()).withFailMessage("Event didn't fire.").isTrue();
    }

    @Test
    void events_revokeGroupFromGroup_groupPresent()
    {
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistry();
        MutableWrapper<Boolean> happened = new MutableWrapper<>(false);
        reg.assignGroupToGroup("doottarget", "dootgroup");

        reg.groupRevoked.register(args ->
        {
            happened.set(true);

            assertThat(args.getTarget()).isSameAs(PermissionsChangedEventTarget.GROUP);
            assertThat(args.getUserTargeted()).isNull();
            assertThat(args.getGroupTargetedId()).isEqualTo("doottarget");
            assertThat(args.getGroupAssociatedId()).isEqualTo("dootgroup");
        });

        reg.revokeGroupFromGroup("doottarget", "dootgroup");
        assertThat(happened.get()).withFailMessage("Event didn't fire.").isTrue();
    }

    @Test
    void events_revokeGroupFromGroup_groupNotPresent()
    {
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistry();
        MutableWrapper<Boolean> happened = new MutableWrapper<>(false);

        reg.groupRevoked.register(args ->
        {
            happened.set(true);

            assertThat(args.getTarget()).isSameAs(PermissionsChangedEventTarget.GROUP);
            assertThat(args.getUserTargeted()).isNull();
            assertThat(args.getGroupTargetedId()).isEqualTo("doottarget");
            assertThat(args.getGroupAssociatedId()).isEqualTo("dootgroup");
        });

        reg.revokeGroupFromGroup("doottarget", "dootgroup");
        assertThat(happened.get()).withFailMessage("Event didn't fire.").isTrue();
    }

    @Test
    void events_revokeDefaultGroup_groupPresent()
    {
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistry();
        MutableWrapper<Boolean> happened = new MutableWrapper<>(false);

        reg.groupRevoked.register(args ->
        {
            happened.set(true);

            assertThat(args.getTarget()).isSameAs(PermissionsChangedEventTarget.DEFAULT_PERMISSIONS);
            assertThat(args.getUserTargeted()).isNull();
            assertThat(args.getGroupTargetedId()).isNull();
            assertThat(args.getGroupAssociatedId()).isEqualTo("dootgroup");
        });

        reg.revokeDefaultGroup("dootgroup");
        assertThat(happened.get()).withFailMessage("Event didn't fire.").isTrue();
    }

    @Test
    void events_revokeDefaultGroup_groupNotPresent()
    {
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistry();
        MutableWrapper<Boolean> happened = new MutableWrapper<>(false);

        reg.groupRevoked.register(args ->
        {
            happened.set(true);

            assertThat(args.getTarget()).isSameAs(PermissionsChangedEventTarget.DEFAULT_PERMISSIONS);
            assertThat(args.getUserTargeted()).isNull();
            assertThat(args.getGroupTargetedId()).isNull();
            assertThat(args.getGroupAssociatedId()).isEqualTo("dootgroup");
        });

        reg.revokeDefaultGroup("dootgroup");
        assertThat(happened.get()).withFailMessage("Event didn't fire.").isTrue();
    }

    @Test
    void events_clear_empty()
    {
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistry();
        MutableWrapper<Boolean> happened = new MutableWrapper<>(false);

        reg.cleared.register(args ->
        {
            happened.set(true);

            assertThat(args.getTarget()).isSameAs(PermissionsChangedEventTarget.ALL);
            assertThat(args.getUserTargeted()).isNull();
            assertThat(args.getGroupTargetedId()).isNull();
        });

        reg.clear();
        assertThat(happened.get()).withFailMessage("Event didn't fire.").isTrue();
    }

    @Test
    void events_clear_populated()
    {
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistry();
        MutableWrapper<Boolean> happened = new MutableWrapper<>(false);
        reg.assignUserPermission("doot", "first.second.third");
        reg.assignGroupPermission("nootgroup", "eins.zwei.drei");
        reg.assignGroupToUser("zoot", "hoot");
        reg.assignDefaultPermission("uno.dos.tres");

        reg.cleared.register(args ->
        {
            happened.set(true);

            assertThat(args.getTarget()).isSameAs(PermissionsChangedEventTarget.ALL);
            assertThat(args.getUserTargeted()).isNull();
            assertThat(args.getGroupTargetedId()).isNull();
        });

        reg.clear();
        assertThat(happened.get()).withFailMessage("Event didn't fire.").isTrue();
    }

    // events_load tests here
}
