package scot.massie.lib.permissions;

import java.util.Objects;

public final class Permission
{
    private Permission(boolean permits, String argument, boolean isIndirect)
    {
        this.permits = permits;
        this.argument = argument;
        this.isIndirect = isIndirect;
    }

    public Permission withArg(String argument)
    { return new Permission(permits, argument, isIndirect); }

    public static final Permission PERMITTING = new Permission(true, null, false);
    public static final Permission PERMITTING_INDIRECTLY = new Permission(true, null, true);
    public static final Permission NEGATING = new Permission(false, null, false);
    public static final Permission NEGATING_INDIRECTLY = new Permission(false, null, true);

    private final boolean permits; // false implies negation
    private final String argument;

    // Is considered indirect where this permission exists as a result of a different permission being declared.
    // i.e. descendants permission for permission "some.permission.path" rather than "some.permission.path.*"
    private final boolean isIndirect;

    public boolean permits()
    { return permits; }

    public boolean negates()
    { return !permits; }

    public boolean hasArg()
    { return argument != null; }

    public String getArg()
    { return argument; }

    public String getArgOr(String defaultVal)
    { return argument != null ? argument : defaultVal; }

    public boolean isIndirect()
    { return isIndirect; }

    @Override
    public boolean equals(Object o)
    {
        if(this == o) return true;
        if(o == null || getClass() != o.getClass()) return false;
        Permission that = (Permission) o;
        return permits == that.permits && isIndirect == that.isIndirect && Objects.equals(argument, that.argument);
    }

    public boolean equals(Permission o)
    {
        if(this == o) return true;
        if(o == null) return false;
        return permits == o.permits && isIndirect == o.isIndirect && Objects.equals(argument, o.argument);
    }

    @Override
    public int hashCode()
    { return Objects.hash(permits, argument, isIndirect); }
}