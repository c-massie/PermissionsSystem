package scot.massie.lib.permissions.decorators;

import scot.massie.lib.permissions.PermissionsRegistryDecoratorTest;

public class AutoUpdatingPermissionsRegistryTest
        extends PermissionsRegistryDecoratorTest<AutoUpdatingPermissionsRegistry<String>>
{
    @Override
    protected AutoUpdatingPermissionsRegistry<String> getNewPermissionsRegistry()
    { return new AutoUpdatingPermissionsRegistry<>(s -> s, s -> s); }
}
