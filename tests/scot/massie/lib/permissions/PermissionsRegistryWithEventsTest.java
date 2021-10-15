package scot.massie.lib.permissions;

import org.junit.jupiter.api.Test;
import scot.massie.lib.permissions.events.PermissionsChangedEventTarget;
import scot.massie.lib.utils.wrappers.MutableWrapper;

import static org.junit.jupiter.api.Assertions.*;
import static org.assertj.core.api.Assertions.*;

public class PermissionsRegistryWithEventsTest extends PermissionsRegistryTest
{
    @Override
    protected PermissionsRegistry<String> getNewPermissionsRegistry()
    { return new PermissionsRegistryWithEvents<>(s -> s, s -> s); }

    protected PermissionsRegistryWithEvents<String> getNewPermissionsRegistryWithEvents()
    { return new PermissionsRegistryWithEvents<>(s -> s, s -> s); }

    @Test
    void events_assignUserPermission()
    {
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistryWithEvents();
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
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistryWithEvents();
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
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistryWithEvents();
        MutableWrapper<Boolean> happened = new MutableWrapper<>(false);

        reg.permissionAssigned.register(args ->
        {
            happened.set(true);

            assertThat(args.getTarget()).isSameAs(PermissionsChangedEventTarget.DEFAULT_PERMISSIONS);
            assertThat(args.getUserTargeted()).isNull();
            assertThat(args.getGroupTargetedId()).isNull();
            assertThat(args.getPermission()).isEqualTo("first.second:someArg");
        });

        reg.assignDefaultGroup("first.second:someArg");
        assertThat(happened.get()).withFailMessage("Event didn't fire.").isTrue();
    }

    @Test
    void events_revokeUserPermission_permissionPresent()
    {
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistryWithEvents();
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
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistryWithEvents();
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
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistryWithEvents();
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
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistryWithEvents();
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
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistryWithEvents();
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
        PermissionsRegistryWithEvents<String> reg = getNewPermissionsRegistryWithEvents();
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
}
