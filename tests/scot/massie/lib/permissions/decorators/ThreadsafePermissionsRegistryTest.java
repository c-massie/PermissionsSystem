package scot.massie.lib.permissions.decorators;

import scot.massie.lib.permissions.GroupMapPermissionsRegistry;
import scot.massie.lib.permissions.GroupMapPermissionsRegistryTest;
import scot.massie.lib.permissions.PermissionsRegistryTest;

public class ThreadsafePermissionsRegistryTest extends PermissionsRegistryTest<ThreadsafePermissionsRegistry<String>>
{
    @Override
    protected ThreadsafePermissionsRegistry<String> getNewPermissionsRegistry()
    { return new ThreadsafePermissionsRegistry<>(s -> s, s -> s); }

    @Override
    protected void createUser(ThreadsafePermissionsRegistry<String> stringThreadsafePermissionsRegistry, String userId)
    {
        // TO DO: Write.
        throw new UnsupportedOperationException("Not yet implemented.");
    }

    @Override
    protected void createGroup(ThreadsafePermissionsRegistry<String> stringThreadsafePermissionsRegistry, String groupName)
    {
        // TO DO: Write.
        throw new UnsupportedOperationException("Not yet implemented.");
    }

    @Override
    protected void createGroup(ThreadsafePermissionsRegistry<String> stringThreadsafePermissionsRegistry, String groupName, int priority)
    {
        // TO DO: Write.
        throw new UnsupportedOperationException("Not yet implemented.");
    }

    @Override
    protected void createGroup(ThreadsafePermissionsRegistry<String> stringThreadsafePermissionsRegistry, String groupName, double priority)
    {
        // TO DO: Write.
        throw new UnsupportedOperationException("Not yet implemented.");
    }
}
