package scot.massie.lib.permissions;

import java.util.List;

public final class Permission
{
    public Permission(boolean isNegation, boolean isWildcard)
    { this(isNegation, isWildcard, null); }

    public Permission(boolean isNegation, boolean isWildcard, String argument)
    { this(!isWildcard && !isNegation, !isWildcard && isNegation, !isNegation, isNegation, argument); }

    Permission(boolean includesExact,
               boolean negatesExact,
               boolean includesDescendants,
               boolean negatesDescendants,
               String argument)
    {
        this.includesExact = includesExact;
        this.negatesExact = negatesExact;
        this.includesDescendants = includesDescendants;
        this.negatesDescendants = negatesDescendants;
        this.argument = argument;
    }

    private final boolean includesExact;
    private final boolean negatesExact;
    private final boolean includesDescendants;
    private final boolean negatesDescendants;
    private final String  argument;

    public boolean includesExact()
    { return includesExact; }

    public boolean negatesExact()
    { return negatesExact; }

    public boolean coversExact()
    { return includesExact || negatesExact; }

    public boolean includesDescendants()
    { return includesDescendants; }

    public boolean negatesDescendants()
    { return negatesDescendants; }

    public boolean coversDescendants()
    { return includesDescendants || negatesDescendants; }

    public boolean hasArg()
    { return argument != null; }

    public String getArg()
    { return argument; }

    public String getArgOr(String defaultVal)
    { return argument != null ? argument : defaultVal; }
}
