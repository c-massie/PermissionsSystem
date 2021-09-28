package scot.massie.lib.permissions;

import java.nio.file.Path;
import java.util.function.Function;

public class ThreadsafePermissionsRegistry<ID extends Comparable<? super ID>> extends PermissionsRegistry<ID>
{
    public ThreadsafePermissionsRegistry(Function<ID, String> idToString, Function<String, ID> idFromString, Path usersFile, Path groupsFile)
    { super(idToString, idFromString, usersFile, groupsFile); }

    public ThreadsafePermissionsRegistry(Function<ID, String> idToString, Function<String, ID> idFromString)
    { super(idToString, idFromString); }
}
