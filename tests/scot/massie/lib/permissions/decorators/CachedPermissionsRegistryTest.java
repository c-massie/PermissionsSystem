package scot.massie.lib.permissions.decorators;

import org.junit.jupiter.api.Test;
import scot.massie.lib.events.InvokableEvent;
import scot.massie.lib.events.SetEvent;
import scot.massie.lib.events.args.EventArgs;
import scot.massie.lib.permissions.GroupMapPermissionsRegistry;
import scot.massie.lib.permissions.PermissionsRegistryDecoratorTest;
import scot.massie.lib.utils.wrappers.IntCounter;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.*;

public class CachedPermissionsRegistryTest
        extends PermissionsRegistryDecoratorTest<CachedPermissionsRegistry<String>>
{
    @Override
    protected CachedPermissionsRegistry<String> getNewPermissionsRegistry()
    { return new CachedPermissionsRegistry<>(s -> s, s -> s); }

    protected CachedPermissionsRegistry<String> getNewPermsRegWithInnerCallEvent(InvokableEvent<EventArgs> event)
    {
        GroupMapPermissionsRegistry<String> inner = new GroupMapPermissionsRegistry<String>(s -> s, s -> s)
        {
            @Override
            public String getUserPermissionArg(String userId, String permission)
            {
                String result = super.getUserPermissionArg(userId, permission);
                event.invoke(new EventArgs() {});
                return result;
            }

            @Override
            public String getDefaultPermissionArg(String permission)
            {
                String result = super.getDefaultPermissionArg(permission);
                event.invoke(new EventArgs() {});
                return result;
            }
        };

        return new CachedPermissionsRegistry<>(inner);
    }



    // These tests assume that every cached function accepting one/two argument(s) implements caching the same way.

    @Test
    void getUserPermissionArg_cacheIsUsed()
    {
        InvokableEvent<EventArgs> e = new SetEvent<>();
        CachedPermissionsRegistry<String> reg = getNewPermsRegWithInnerCallEvent(e);
        IntCounter c = new IntCounter();
        e.register(args -> c.incr());

        reg.assignUserPermission("foo", "my.permission.doot: some arg");

        assertThat(c.get()).isEqualTo(0);
        assertThat(reg.getUserPermissionArg("foo", "my.permission.doot")).isEqualTo("some arg");
        assertThat(c.get()).isEqualTo(1);
        assertThat(reg.getUserPermissionArg("foo", "my.permission.doot")).isEqualTo("some arg");
        assertThat(c.get()).isEqualTo(1);
    }

    @Test
    void getDefaultPermissionArg_cacheIsUsed()
    {
        InvokableEvent<EventArgs> e = new SetEvent<>();
        CachedPermissionsRegistry<String> reg = getNewPermsRegWithInnerCallEvent(e);
        IntCounter c = new IntCounter();
        e.register(args -> c.incr());

        reg.assignDefaultPermission("my.permission.doot: some arg");

        assertThat(c.get()).isEqualTo(0);
        assertThat(reg.getDefaultPermissionArg("my.permission.doot")).isEqualTo("some arg");
        assertThat(c.get()).isEqualTo(1);
        assertThat(reg.getDefaultPermissionArg("my.permission.doot")).isEqualTo("some arg");
        assertThat(c.get()).isEqualTo(1);
    }
}
