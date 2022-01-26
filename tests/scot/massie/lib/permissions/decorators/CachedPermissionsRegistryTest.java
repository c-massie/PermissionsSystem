package scot.massie.lib.permissions.decorators;

import scot.massie.lib.permissions.PermissionsRegistryDecoratorTest;

public class CachedPermissionsRegistryTest
        extends PermissionsRegistryDecoratorTest<CachedPermissionsRegistry<String>>
{
    @Override
    protected CachedPermissionsRegistry<String> getNewPermissionsRegistry()
    { return new CachedPermissionsRegistry<>(s -> s, s -> s); }
}
