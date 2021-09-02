package scot.massie.lib.permissions;

import com.sun.istack.internal.NotNull;
import com.sun.istack.internal.Nullable;
import jdk.nashorn.internal.ir.annotations.Immutable;

import java.util.Objects;

/**
 * A single permission, primarily for use in {@link PermissionSet}. Does not contain the path of each permission, as
 * that's handled by PermissionSet itself, but contains all other information.
 */
@Immutable
public final class Permission
{
    //region Initialisation
    private Permission(boolean permits, String argument, boolean isIndirect)
    {
        this.permits = permits;
        this.argument = argument;
        this.isIndirect = isIndirect;
    }

    /**
     * Gets a variant of the permission this is called on, with the given string as an associated string argument.
     * @param argument The string argument to get a copy of this argument associated with.
     * @return A copy of the permission this is called on, with the given string as an associated string
     *         argument.
     */
    @NotNull
    public Permission withArg(String argument)
    { return new Permission(permits, argument, isIndirect); }

    /**
     * Gets a variant of the permission this is called on, marked as being the indirect consequence of another
     * permission.
     * @return A copy of the permission this is called on, marked as being indirect. Returns the same object where the
     *         call results in no change.
     */
    @NotNull
    public Permission indirectly()
    {
        if(argument == null)
            return permits ? PERMITTING_INDIRECTLY : NEGATING_INDIRECTLY;

        if(isIndirect)
            return this;

        return new Permission(permits, argument, true);
    }
    //endregion

    //region Default instances
    /**
     * Permission permitting something, which is explicitly specified.
     */
    public static final Permission PERMITTING = new Permission(true, null, false);

    /**
     * Permission permitting something, which is an indirect consequence of another permission.
     */
    public static final Permission PERMITTING_INDIRECTLY = new Permission(true, null, true);

    /**
     * Permission negating other permissions, which is explicitly specified.
     */
    public static final Permission NEGATING = new Permission(false, null, false);

    /**
     * Permission negating other permissions, which is an indirect consequence of another permission.
     */
    public static final Permission NEGATING_INDIRECTLY = new Permission(false, null, true);
    //endregion

    //region Fields
    /**
     * Whether or not this permission permits something. False implies it negates other permissions instead.
     */
    private final boolean permits;

    /**
     * The string argument associated with this permission. Null implies there is no argument associated with this
     * permission.
     */
    @Nullable
    private final String argument;

    /**
     * Whether or not the permission exists as the result of a different permission being declared. e.g. in
     * {@link PermissionSet}, the permission "some.permission.path" implies the permission "some.permission.path.*".
     */
    private final boolean isIndirect;
    //endregion

    //region Accessors
    /**
     * Gets whether or not this permission permits something.
     * @return True if it permits something. Otherwise, (e.g. if it negates other permissions) returns false.
     */
    public boolean permits()
    { return permits; }

    /**
     * Gets whether or not this permission negates other permissions.
     * @return True if it negates other permissions. Otherwise, (e.g. if it permits something) returns false.
     */
    public boolean negates()
    { return !permits; }

    /**
     * Gets whether or not this permission has a string argument associated with it.
     * @return True if it has a string argument associated with it. Otherwise, false.
     */
    public boolean hasArg()
    { return argument != null; }

    /**
     * Gets the string argument associated with this permission.
     * @return The string argument associated with this permission. If there is no string argument associated with this
     *         permission, returns null instead.
     */
    @Nullable
    public String getArg()
    { return argument; }

    /**
     * Gets the string argument associated with this permission, or the provided default string if there is none.
     * @param defaultVal The string to return if there is no string argument associated with this permission.
     * @return The string argument associated with this permission. Otherwise, the provided default string instead.
     */
    @Nullable
    public String getArgOr(String defaultVal)
    { return argument != null ? argument : defaultVal; }

    /**
     * Gets whether or not this permission is the indirect consequence of the presence of another permission.
     * @return True if it is the indirect consequence of the presence of another permission. Otherwise, false.
     */
    public boolean isIndirect()
    { return isIndirect; }
    //endregion

    //region Overloads

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        if(!permits)
            sb.append("-");

        sb.append("permission");

        if(isIndirect)
            sb.append("(indirectly)");

        if(hasArg())
            sb.append(": ").append(argument);

        return sb.toString();
    }

    /**
     * <p>Gets whether this permission is equal to the provided object.</p>
     *
     * <p>Permissions are only considered equal to other permissions.</p>
     *
     * <p>Two permissions are considered equal where all of the following are true:</p>
     * <ul>
     *     <il><p>They have the same associated string argument, or both lack them.</p></il>
     *     <il><p>They are both directly declared, or both indirect consequences of the presence of other permissions.</p></il>
     *     <il><p>They both permit something, or they both negate other permissions.</p></il>
     * </ul>
     * @param o The object to test for equality with this permission.
     * @return True if the two objects are both permissions and are equal as defined above. Otherwise, false.
     */
    @Override
    public boolean equals(Object o)
    {
        if(this == o) return true;
        if(o == null || getClass() != o.getClass()) return false;
        Permission that = (Permission) o;
        return permits == that.permits && isIndirect == that.isIndirect && Objects.equals(argument, that.argument);
    }

    /**
     * <p>Gets whether this permission is equal to the provided permission.</p>
     *
     * <p>Two permissions are considered equal where all are true:</p>
     * <ul>
     *     <il><p>They have the same associated string argument, or both lack them.</p></il>
     *     <il><p>They are both directly declared, or both indirect consequences of the presence of other permissions.</p></il>
     *     <il><p>They both permit something, or they both negate other permissions.</p></il>
     * </ul>
     * @param o The other permission to test for equality with this permission.
     * @return True if the two objects are equal as defined above. Otherwise, false.
     */
    public boolean equals(Permission o)
    {
        if(this == o) return true;
        if(o == null) return false;
        return permits == o.permits && isIndirect == o.isIndirect && Objects.equals(argument, o.argument);
    }

    @Override
    public int hashCode()
    { return Objects.hash(permits, argument, isIndirect); }
    //endregion
}