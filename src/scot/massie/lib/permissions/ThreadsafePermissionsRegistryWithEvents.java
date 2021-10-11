package scot.massie.lib.permissions;

import java.nio.file.Path;
import java.util.function.Function;

public class ThreadsafePermissionsRegistryWithEvents<ID extends Comparable<? super ID>>
        extends PermissionsRegistryWithEvents<ID>
{

    public ThreadsafePermissionsRegistryWithEvents(Function<ID, String> idToString,
                                                   Function<String, ID> idFromString,
                                                   Path usersFile,
                                                   Path groupsFile)
    { super(idToString, idFromString, usersFile, groupsFile); }

    public ThreadsafePermissionsRegistryWithEvents(Function<ID, String> idToString, Function<String, ID> idFromString)
    { super(idToString, idFromString); }
}
