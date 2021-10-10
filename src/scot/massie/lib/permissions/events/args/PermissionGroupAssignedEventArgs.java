package scot.massie.lib.permissions.events.args;

import scot.massie.lib.permissions.PermissionsRegistryWithEvents;
import scot.massie.lib.permissions.events.PermissionsChangedEventTarget;

/**
 * Event args for when a group is assigned.
 *
 * @param <ID> The type of the IDs used to identify users in the permissions registry this eventargs object belongs
 *             to.
 */
public class PermissionGroupAssignedEventArgs<ID extends Comparable<? super ID>>
        extends PermissionGroupEventArgs<ID>
{
    /**
     * Creates a new event args object.
     *
     * @param registry        The registry the event this eventargs object is being created for belongs to.
     * @param target          The type of entry in the registry that is being directly targeted.
     * @param userTargeted    Where a user is being targeted, the user that was targeted. If a user was not directly
     *                        targeted, this should always be null.
     * @param groupTargetedId Where a group is being targeted, the ID of the group that was targeted. If a group was
     *                        not directly targeted, this should always be null.
     * @param groupAssignedId The ID of the group that was assigned in the action that raised this event.
     */
    protected PermissionGroupAssignedEventArgs(PermissionsRegistryWithEvents<ID> registry,
                                               PermissionsChangedEventTarget target,
                                               ID userTargeted,
                                               String groupTargetedId,
                                               String groupAssignedId)
    {
        super(registry, target, userTargeted, groupTargetedId, groupAssignedId);
    }

    /**
     * Creates a new event args object, for where a group is added to the default permissions.
     *
     * @param registry        The registry the event this event args object is for belongs to.
     * @param groupAssignedId The ID of the group that was added to the default permissions.
     * @param <ID>            The type users in the registry are identified by.
     * @return A new event args object.
     */
    public static <ID extends Comparable<? super ID>> PermissionGroupAssignedEventArgs<ID>
    newAboutDefaultPermissions(PermissionsRegistryWithEvents<ID> registry, String groupAssignedId)
    {
        return new PermissionGroupAssignedEventArgs<>(
                registry, PermissionsChangedEventTarget.DEFAULT_PERMISSIONS, null, null, groupAssignedId);
    }

    /**
     * Creates a new event args object, for where a user is directly assigned a group.
     *
     * @param registry        The registry the event this event args object is for belongs to.
     * @param userId          The ID of the user that was assigned a permission.
     * @param groupAssignedId The ID of the group that was assigned to the user.
     * @param <ID>            The type users in the registry are identified by.
     * @return A new event args object.
     */
    public static <ID extends Comparable<? super ID>> PermissionGroupAssignedEventArgs<ID>
    newAboutUser(PermissionsRegistryWithEvents<ID> registry, ID userId, String groupAssignedId)
    {
        return new PermissionGroupAssignedEventArgs<>(
                registry, PermissionsChangedEventTarget.USER, userId, null, groupAssignedId);
    }

    /**
     * Creates a new event args object, for where a group is directly assigned a group.
     *
     * @param registry        The registry the event this event args object is for belongs to.
     * @param groupTargetedId The ID of the group that was assigned a group.
     * @param groupAssignedId The ID of the group that was assigned to the targeted group.
     * @param <ID>            The type users in the registry are identified by.
     * @return A new event args object.
     */
    public static <ID extends Comparable<? super ID>> PermissionGroupAssignedEventArgs<ID>
    newAboutGroup(PermissionsRegistryWithEvents<ID> registry, String groupTargetedId, String groupAssignedId)
    {
        return new PermissionGroupAssignedEventArgs<>(
                registry, PermissionsChangedEventTarget.GROUP, null, groupTargetedId, groupAssignedId);
    }
}
