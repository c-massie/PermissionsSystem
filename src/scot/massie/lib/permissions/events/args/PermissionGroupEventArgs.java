package scot.massie.lib.permissions.events.args;

import scot.massie.lib.permissions.decorators.PermissionsRegistryWithEvents;
import scot.massie.lib.permissions.events.PermissionsChangedEventTarget;

/**
 * Event args for when a group is assigned or revoked.
 *
 * @param <ID> The type of the IDs used to identify users in the permissions registry this eventargs object belongs
 *             to.
 */
public class PermissionGroupEventArgs<ID extends Comparable<? super ID>> extends PermissionsChangedEventArgs<ID>
{
    /**
     * The ID of the group associated with the action that raised this event. Where a group is targeted, this isn't
     * the group that was targeted, but rather the group that was assigned/revoked to/from that group.
     */
    final String groupId;

    /**
     * Creates a new event args object.
     *
     * @param registry      The registry the event this eventargs object is being created for belongs to.
     * @param target        The type of entry in the registry that is being directly targeted.
     * @param userTargeted  Where a user is being targeted, the user that was targeted. If a user was not directly
     *                      targeted, this should always be null.
     * @param groupTargeted Where a group is being targeted, the group that was targeted. If a group was not
     *                      directly targeted, this should always be null.
     * @param groupId       The ID of the group associated with (not targeted by) the action that raised the event.
     */
    protected PermissionGroupEventArgs(PermissionsRegistryWithEvents<ID> registry,
                                       PermissionsChangedEventTarget target,
                                       ID userTargeted,
                                       String groupTargeted,
                                       String groupId)
    {
        super(registry, target, userTargeted, groupTargeted);
        this.groupId = groupId;
    }

    /**
     * Gets the ID of the group associated with the action that raised this event. Where a group is targeted, this
     * isn't the group that was targeted,but rather the group that was assigned/revoked to/from that group.
     *
     * @return The group associated with the action that raised the event.
     */
    public String getGroupAssociatedId()
    {
        return groupId;
    }
}
