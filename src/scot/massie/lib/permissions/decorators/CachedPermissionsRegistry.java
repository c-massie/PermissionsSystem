package scot.massie.lib.permissions.decorators;

import scot.massie.lib.permissions.PermissionsRegistry;
import scot.massie.lib.permissions.PermissionsRegistryDecorator;

import java.nio.file.Path;
import java.util.function.Function;

public class CachedPermissionsRegistry<ID extends Comparable<? super ID>> extends PermissionsRegistryDecorator<ID>
{
    public CachedPermissionsRegistry(Function<ID, String> idToString,
                                     Function<String, ID> idFromString,
                                     Path usersFile,
                                     Path groupsFile)
    { super(idToString, idFromString, usersFile, groupsFile); }

    public CachedPermissionsRegistry(Function<ID, String> idToString, Function<String, ID> idFromString)
    { super(idToString, idFromString); }

    public CachedPermissionsRegistry(PermissionsRegistry<ID> inner)
    { super(inner); }
}
