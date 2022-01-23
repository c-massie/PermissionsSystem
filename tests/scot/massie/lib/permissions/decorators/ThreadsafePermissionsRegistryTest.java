package scot.massie.lib.permissions.decorators;

import scot.massie.lib.permissions.PermissionsRegistryDecoratorTest;

public class ThreadsafePermissionsRegistryTest
        extends PermissionsRegistryDecoratorTest<ThreadsafePermissionsRegistry<String>>
{
    @Override
    protected ThreadsafePermissionsRegistry<String> getNewPermissionsRegistry()
    { return new ThreadsafePermissionsRegistry<>(s -> s, s -> s); }
}
