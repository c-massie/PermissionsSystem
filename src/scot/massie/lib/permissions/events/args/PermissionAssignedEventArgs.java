package scot.massie.lib.permissions.events.args;

import scot.massie.lib.permissions.PermissionsRegistryWithEvents;
import scot.massie.lib.permissions.events.PermissionsChangedEventTarget;

/**
 * Event args for when a permission is assigned.
 *
 * @param <ID> The type of the IDs used to identify users in the permissions registry this eventargs object belongs
 *             to.
 */
public class PermissionAssignedEventArgs<ID extends Comparable<? super ID>>
        extends PermissionEventArgs<ID>
{
    /**
     * Creates a new event args object.
     *
     * @param registry      The registry the event this eventargs object is being created for belongs to.
     * @param target        The type of entry in the registry that is being directly targeted.
     * @param userTargeted  Where a user is being targeted, the user that was targeted. If a user was not directly
     *                      targeted, this should always be null.
     * @param groupTargeted Where a group is being targeted, the group that was targeted. If a group was not
     *                      directly targeted, this should always be null.
     * @param permission    The permission that was assigned in the action that raised this event.
     */
    protected PermissionAssignedEventArgs(PermissionsRegistryWithEvents<ID> registry,
                                          PermissionsChangedEventTarget target,
                                          ID userTargeted,
                                          String groupTargeted,
                                          String permission)
    {
        super(registry, target, userTargeted, groupTargeted, permission);
    }

    /**
     * Creates a new event args object, for where a permission is added to the default permissions.
     *
     * @param registry           The registry the event this event args object is for belongs to.
     * @param permissionAssigned The permission that was added to the default permissions.
     * @param <ID>               The type users in the registry are identified by.
     * @return A new event args object.
     */
    public static <ID extends Comparable<? super ID>> PermissionAssignedEventArgs<ID>
    newAboutDefaultPermissions(PermissionsRegistryWithEvents<ID> registry, String permissionAssigned)
    {
        return new PermissionAssignedEventArgs<>(
                registry, PermissionsChangedEventTarget.DEFAULT_PERMISSIONS, null, null, permissionAssigned);
    }

    /**
     * Creates a new event args object, for where a user is directly assigned a permission.
     *
     * @param registry           The registry the event this event args object is for belongs to.
     * @param userId             The ID of the user that was assigned a permission.
     * @param permissionAssigned The permission that was assigned to the user.
     * @param <ID>               The type users in the registry are identified by.
     * @return A new event args object.
     */
    public static <ID extends Comparable<? super ID>> PermissionAssignedEventArgs<ID>
    newAboutUser(PermissionsRegistryWithEvents<ID> registry, ID userId, String permissionAssigned)
    {
        return new PermissionAssignedEventArgs<>(
                registry, PermissionsChangedEventTarget.USER, userId, null, permissionAssigned);
    }

    /**
     * Creates a new event args object, for where a group is directly assigned a permission.
     *
     * @param registry           The registry the event this event args object is for belongs to.
     * @param groupId            The ID of the group that was assigned a permission.
     * @param permissionAssigned The permission that was assigned to the group.
     * @param <ID>               The type users in the registry are identified by.
     * @return A new event args object.
     */
    public static <ID extends Comparable<? super ID>> PermissionAssignedEventArgs<ID>
    newAboutGroup(PermissionsRegistryWithEvents<ID> registry, String groupId, String permissionAssigned)
    {
        return new PermissionAssignedEventArgs<>(
                registry, PermissionsChangedEventTarget.GROUP, null, groupId, permissionAssigned);
    }

    /**
     * Gets whether the permission being assigned is a negating permission.
     * @return True if the permission being assigned is a negating permission. Otherwise, false.
     */
    public boolean permissionIsNegating()
    { return this.permission.trim().startsWith("-"); }

    /**
     * Gets whether the permission being assigned is a permitting permission.
     * @return True if the permission being assigned is a permitting permission. Otherwise, false.
     */
    public boolean permissionIsPermitting()
    { return !this.permission.trim().startsWith("-"); }

    /**
     * Gets the path of the permission assigned.
     * @return The path of the permission assigned.
     */
    public String getPermissionPath()
    {
        String result = permission.split(":", 2)[0].trim();

        if(result.startsWith("-"))
            result = result.substring(1).trim();

        return result;
    }

    /**
     * Gets the argument text of the assigned permission.
     * @return The argument text of the assigned permission, or null if no argument was passed to the permission.
     */
    public String getPermissionArg()
    {
        String[] permissionParts = permission.split(":", 2);
        return (permissionParts.length >= 2) ? permissionParts[1] : null;
    }
}
