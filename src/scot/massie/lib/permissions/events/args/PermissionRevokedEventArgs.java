package scot.massie.lib.permissions.events.args;

import scot.massie.lib.permissions.PermissionsRegistryWithEvents;
import scot.massie.lib.permissions.events.PermissionsChangedEventTarget;

/**
 * Event args for when a permission is revoked.
 *
 * @param <ID> The type of the IDs used to identify users in the permissions registry this eventargs object belongs
 *             to.
 */
public class PermissionRevokedEventArgs<ID extends Comparable<? super ID>>
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
     * @param permission    The permission that was revoked in the action that raised this event.
     */
    protected PermissionRevokedEventArgs(PermissionsRegistryWithEvents<ID> registry,
                                         PermissionsChangedEventTarget target,
                                         ID userTargeted,
                                         String groupTargeted,
                                         String permission)
    {
        super(registry, target, userTargeted, groupTargeted, permission);
    }

    /**
     * Creates a new event args object, for where a permission is removed from the default permissions.
     *
     * @param registry           The registry the event this event args object is for belongs to.
     * @param permissionAssigned The permission that was removed from the default permissions.
     * @param <ID>               The type users in the registry are identified by.
     * @return A new event args object.
     */
    public static <ID extends Comparable<? super ID>> PermissionRevokedEventArgs<ID>
    newAboutDefaultPermissions(PermissionsRegistryWithEvents<ID> registry, String permissionAssigned)
    {
        return new PermissionRevokedEventArgs<>(
                registry, PermissionsChangedEventTarget.DEFAULT_PERMISSIONS, null, null, permissionAssigned);
    }

    /**
     * Creates a new event args object, for where a permission is directly revoked from a user.
     *
     * @param registry           The registry the event this event args object is for belongs to.
     * @param userId             The ID of the user that had a permission revoked.
     * @param permissionAssigned The permission that was revoked from the user.
     * @param <ID>               The type users in the registry are identified by.
     * @return A new event args object.
     */
    public static <ID extends Comparable<? super ID>> PermissionRevokedEventArgs<ID>
    newAboutUser(PermissionsRegistryWithEvents<ID> registry, ID userId, String permissionAssigned)
    {
        return new PermissionRevokedEventArgs<>(
                registry, PermissionsChangedEventTarget.USER, userId, null, permissionAssigned);
    }

    /**
     * Creates a new event args object, for where a permission is directly revoked from a group.
     *
     * @param registry           The registry the event this event args object is for belongs to.
     * @param groupId            The ID of the group that had a permission revoked.
     * @param permissionAssigned The permission that was revoked from the group.
     * @param <ID>               The type users in the registry are identified by.
     * @return A new event args object.
     */
    public static <ID extends Comparable<? super ID>> PermissionRevokedEventArgs<ID>
    newAboutGroup(PermissionsRegistryWithEvents<ID> registry, String groupId, String permissionAssigned)
    {
        return new PermissionRevokedEventArgs<>(
                registry, PermissionsChangedEventTarget.GROUP, null, groupId, permissionAssigned);
    }
}
