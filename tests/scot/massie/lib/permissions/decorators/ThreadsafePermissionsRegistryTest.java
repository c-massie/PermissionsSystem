package scot.massie.lib.permissions.decorators;

import scot.massie.lib.permissions.PermissionsRegistry;
import scot.massie.lib.permissions.PermissionsRegistryTest;
import scot.massie.lib.permissions.decorators.ThreadsafePermissionsRegistry;

public class ThreadsafePermissionsRegistryTest extends PermissionsRegistryTest
{
    @Override
    protected PermissionsRegistry<String> getNewPermissionsRegistry()
    { return new ThreadsafePermissionsRegistry<>(s -> s, s -> s); }
}
