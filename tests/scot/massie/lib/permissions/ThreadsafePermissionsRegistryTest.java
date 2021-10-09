package scot.massie.lib.permissions;

public class ThreadsafePermissionsRegistryTest extends PermissionsRegistryTest
{
    @Override
    protected PermissionsRegistry<String> getNewPermissionsRegistry()
    { return new PermissionsRegistry<>(s -> s, s -> s); }
}
