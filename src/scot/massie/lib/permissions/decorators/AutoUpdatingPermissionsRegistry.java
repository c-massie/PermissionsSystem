package scot.massie.lib.permissions.decorators;

import scot.massie.lib.permissions.GroupMapPermissionsRegistry;
import scot.massie.lib.permissions.PermissionsRegistry;
import scot.massie.lib.permissions.PermissionsRegistryDecorator;

import java.nio.file.Path;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * <p>A {@link PermissionsRegistry} decorator that, when prompted, updates the contents of its enclosed registry
 * according to provided criteria.</p>
 * @param <ID>The type of the unique identifier used to represent users.
 */
public class AutoUpdatingPermissionsRegistry<ID extends Comparable<? super ID>> extends PermissionsRegistryDecorator<ID>
{
    /**
     * Suppliers for the players that should have given permissions, and the permissions they should have.
     */
    Map<Supplier<Collection<ID>>, String> autoUserPerms = new HashMap<>();

    /**
     * Suppliers for the players that should have specified groups, and the groups they should have.
     */
    Map<Supplier<Collection<ID>>, String> autoUserGroups = new HashMap<>();

    /**
     * Suppliers for the players that should have given permissions exclusively, and the permissions they should have.
     */
    Map<Supplier<Collection<ID>>, String> exclusiveAutoUserPerms = new HashMap<>();

    /**
     * Suppliers for the players that should have specified groups exclusively, and the groups they should have.
     */
    Map<Supplier<Collection<ID>>, String> exclusiveAutoUserGroups = new HashMap<>();

    /**
     * Creates a new auto-updating permissions registry, with the ability to save to/load from files.
     * @param idToString The conversion for turning a user ID into a reversible string representation of it.
     * @param idFromString The conversion for turning a user ID as a string string back into a user ID object.
     * @param usersFile The filepath of the users permissions save file.
     * @param groupsFile The filepath of the groups permissions save file.
     */
    public AutoUpdatingPermissionsRegistry(Function<ID, String> idToString,
                                           Function<String, ID> idFromString,
                                           Path usersFile,
                                           Path groupsFile)
    { super(idToString, idFromString, usersFile, groupsFile); }

    /**
     * Creates a new auto-updating permissions registry, without the ability to save to/load from files.
     * @param idToString The conversion for turning a user ID into a reversible string representation of it.
     * @param idFromString The conversion for turning a user ID as a string string back into a user ID object.
     */
    public AutoUpdatingPermissionsRegistry(Function<ID, String> idToString, Function<String, ID> idFromString)
    { super(idToString, idFromString); }

    /**
     * Wraps an existing permissions registry in an auto-updating permissions registry, which will update its contents
     * when prompted.
     * @param inner The wrapped permissions registry.
     */
    public AutoUpdatingPermissionsRegistry(GroupMapPermissionsRegistry<ID> inner)
    { super(inner); }

    /**
     * Applies the provided rules about who should have what permissions.
     */
    public void autoUpdate()
    {
        for(Map.Entry<Supplier<Collection<ID>>, String> e : autoUserPerms.entrySet())
        {
            Collection<ID> userIds = e.getKey().get();
            String perm = e.getValue();

            for(ID id : userIds)
                inner.assignUserPermission(id, perm);
        }

        for(Map.Entry<Supplier<Collection<ID>>, String> e : autoUserGroups.entrySet())
        {
            Collection<ID> userIds = e.getKey().get();
            String groupName = e.getValue();

            for(ID id : userIds)
                inner.assignGroupToUser(id, groupName);
        }

        for(Map.Entry<Supplier<Collection<ID>>, String> e : exclusiveAutoUserPerms.entrySet())
        {
            Set<ID> userIds = new HashSet<>(e.getKey().get());
            String perm = e.getValue();

            for(ID id : userIds)
                inner.assignUserPermission(id, perm);

            for(ID id : inner.getUsers())
                if(!userIds.contains(id))
                    inner.revokeUserPermission(id, perm);
        }

        for(Map.Entry<Supplier<Collection<ID>>, String> e : exclusiveAutoUserGroups.entrySet())
        {
            Set<ID> userIds = new HashSet<>(e.getKey().get());
            String groupName = e.getValue();

            for(ID id : userIds)
                inner.assignGroupToUser(id, groupName);

            for(ID id : inner.getUsers())
                if(!userIds.contains(id))
                    inner.revokeGroupFromUser(id, groupName);
        }
    }

    /**
     * Specifies that players specified by the provided supplier should be given the provided permission.
     * @param permission The permission the players specified by the supplier should have.
     * @param usersThatShouldHavePermissionSupplier The supplier supplying players that should have the permission.
     */
    public void addAutoPerm(String permission, Supplier<Collection<ID>> usersThatShouldHavePermissionSupplier)
    { autoUserPerms.put(usersThatShouldHavePermissionSupplier, permission); }

    /**
     * Specifies that players specified by the provided players should be given the provided permission.
     * @param permission The permission the players specified by the supplier should have.
     * @param permissionIsExclusiveToThoseUsers Whether or not to remove the permission from players that are not
     *                                          specified by the provided supplier. Note that this does not affect
     *                                          groups or the default permissions.
     * @param usersThatShouldHavePermissionSupplier The supplier supplying players that should have the permission.
     */
    public void addAutoPerm(String                   permission,
                            boolean                  permissionIsExclusiveToThoseUsers,
                            Supplier<Collection<ID>> usersThatShouldHavePermissionSupplier)
    {
        if(permissionIsExclusiveToThoseUsers)
            exclusiveAutoUserPerms.put(usersThatShouldHavePermissionSupplier, permission);
        else
            autoUserPerms.put(usersThatShouldHavePermissionSupplier, permission);
    }

    /**
     * Specifies that players specified by the provided supplier should be given the specified group.
     * @param groupName The name of the group players specified by the supplier should have.
     * @param usersThatShouldHaveGroupSupplier The supplier supplying players that should have the group.
     */
    public void addAutoGroup(String groupName, Supplier<Collection<ID>> usersThatShouldHaveGroupSupplier)
    { autoUserPerms.put(usersThatShouldHaveGroupSupplier, groupName); }

    /**
     * Specifies that players specified by the provided supplier should be given the specified group.
     * @param groupName The name of the group players specified by the supplier should have.
     * @param groupIsExclusiveToThoseUsers Whether or not to remove the group from players that are not specified by the
     *                                     provided supplier. Note that this does not affect groups or the default
     *                                     permissions.
     * @param usersThatShouldHaveGroupSupplier The supplier supplying players that should have the group.
     */
    public void addAutoGroup(String                   groupName,
                             boolean                  groupIsExclusiveToThoseUsers,
                             Supplier<Collection<ID>> usersThatShouldHaveGroupSupplier)
    {
        if(groupIsExclusiveToThoseUsers)
            exclusiveAutoUserGroups.put(usersThatShouldHaveGroupSupplier, groupName);
        else
            autoUserGroups.put(usersThatShouldHaveGroupSupplier, groupName);
    }
}
