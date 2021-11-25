package scot.massie.lib.permissions.events.args;

import scot.massie.lib.permissions.decorators.PermissionsRegistryWithEvents;
import scot.massie.lib.permissions.events.PermissionsChangedEventTarget;

/**
 * Event args for when a group is revoked.
 *
 * @param <ID> The type of the IDs used to identify users in the permissions registry this eventargs object belongs
 *             to.
 */
public class PermissionGroupRevokedEventArgs<ID extends Comparable<? super ID>>
        extends PermissionGroupEventArgs<ID>
{
    /**
     * Creates a new event args object.
     *
     * @param registry        The registry the event this eventargs object is being created for belongs to.
     * @param target          The type of entry in the registry that is being directly targeted.
     * @param userTargeted    Where a user is being targeted, the user that was targeted. If a user was not directly
     *                        targeted, this should always be null.
     * @param groupTargetedId Where a group is being targeted, the group that was targeted. If a group was not
     *                        directly targeted, this should always be null.
     * @param groupRevokedId  The group that was revoked in the action that raised this event.
     */
    protected PermissionGroupRevokedEventArgs(PermissionsRegistryWithEvents<ID> registry,
                                              PermissionsChangedEventTarget target,
                                              ID userTargeted,
                                              String groupTargetedId,
                                              String groupRevokedId)
    {
        super(registry, target, userTargeted, groupTargetedId, groupRevokedId);
    }

    /**
     * Creates a new event args object, for where a group is removed from to the default permissions.
     *
     * @param registry       The registry the event this event args object is for belongs to.
     * @param groupRevokedId The ID of the group that was removed from the default permissions.
     * @param <ID>           The type users in the registry are identified by.
     * @return A new event args object.
     */
    public static <ID extends Comparable<? super ID>> PermissionGroupRevokedEventArgs<ID>
    newAboutDefaultPermissions(PermissionsRegistryWithEvents<ID> registry, String groupRevokedId)
    {
        return new PermissionGroupRevokedEventArgs<>(
                registry, PermissionsChangedEventTarget.DEFAULT_PERMISSIONS, null, null, groupRevokedId);
    }

    /**
     * Creates a new event args object, for where a group is directly revoked from a user.
     *
     * @param registry       The registry the event this event args object is for belongs to.
     * @param userId         The ID of the user that had a group revoked.
     * @param groupRevokedId The ID of the group that was revoked from the user.
     * @param <ID>           The type users in the registry are identified by.
     * @return A new event args object.
     */
    public static <ID extends Comparable<? super ID>> PermissionGroupRevokedEventArgs<ID>
    newAboutUser(PermissionsRegistryWithEvents<ID> registry, ID userId, String groupRevokedId)
    {
        return new PermissionGroupRevokedEventArgs<>(
                registry, PermissionsChangedEventTarget.USER, userId, null, groupRevokedId);
    }

    /**
     * Creates a new event args object, for where a group is directly revoked from a group.
     *
     * @param registry        The registry the event this event args object is for belongs to.
     * @param groupTargetedId The ID of the group that had a group revoked.
     * @param groupRevokedId  The ID of the group that was revoked from the targeted group.
     * @param <ID>            The type users in the registry are identified by.
     * @return A new event args object.
     */
    public static <ID extends Comparable<? super ID>> PermissionGroupRevokedEventArgs<ID>
    newAboutGroup(PermissionsRegistryWithEvents<ID> registry, String groupTargetedId, String groupRevokedId)
    {
        return new PermissionGroupRevokedEventArgs<>(
                registry, PermissionsChangedEventTarget.GROUP, null, groupTargetedId, groupRevokedId);
    }
}
