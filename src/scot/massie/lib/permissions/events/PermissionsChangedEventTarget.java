package scot.massie.lib.permissions.events;

/**
 * Specifier for what type of entry in the permissions registry is being targeted in a particular contents changed
 * event.
 */
public enum PermissionsChangedEventTarget
{
    /**
     * Events marked as affecting all entry types may affect (and likely do) the users, groups, and default
     * permissions of the registry.
     */
    ALL,

    /**
     * Events with this value affect individual users in the permissions registry.
     */
    USER,

    /**
     * Events with this value affect groups in the permissions registry. They will not affect users directly, but
     * may affect the users or groups they have indirectly by affecting the groups they have.
     */
    GROUP,

    /**
     * Events with this value affect the default permissions of the permissions registry. They will not affect users
     * or groups directly, but may affect the users or groups they have indirectly by affecting the default
     * permissions/groups which are fallen back on after checking the groups a particular user or group has.
     */
    DEFAULT_PERMISSIONS
}
