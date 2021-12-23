package scot.massie.lib.permissions;

import com.sun.istack.internal.NotNull;
import scot.massie.lib.functionalinterfaces.Condition;

import java.util.Objects;

/**
 * A single permission, primarily for use in {@link PermissionSet}, with a condition attached that determines whether or
 * not it should be considered.
 * @see Permission
 */
public class ConditionalPermission extends Permission
{
    /**
     * The condition that determines whether this permission should currently be considered.
     */
    final Condition condition;

    protected ConditionalPermission(boolean permits, String argument, boolean isIndirect, Condition condition)
    {
        super(permits, argument, isIndirect);
        this.condition = condition;
    }

    @Override
    @NotNull
    public ConditionalPermission withArg(String argument)
    { return new ConditionalPermission(permits, argument, isIndirect, condition); }

    @Override
    @NotNull
    public ConditionalPermission indirectly()
    {
        if(isIndirect)
            return this;

        return new ConditionalPermission(permits, argument, true, condition);
    }

    /**
     * Whether or not this permission should be considered. That is, whether or not the condition this permission
     * considers is currently true.
     * @return True if this permission's condition returns true and this permission should be considered. Otherwise,
     *         false.
     */
    @Override
    public boolean shouldBeConsidered()
    { return condition.test(); }

    /**
     * Whether or not this permission should be ignored. That is, whether or not the condition this permission considers
     * is currently false. The inverse of {@link #shouldBeConsidered()}.
     * @return True if this permission's condition returns false and this permission should be ignore and not
     *         considered. Otherwise, false.
     */
    @Override
    public boolean shouldBeIgnored()
    { return !condition.test(); }

    @Override
    public String toString()
    { return "(conditionally) " + super.toString(); }

    @Override
    public boolean equals(Object o)
    {
        if(this == o) return true;
        if(o == null || getClass() != o.getClass()) return false;
        if(!super.equals(o)) return false;
        ConditionalPermission that = (ConditionalPermission)o;
        return condition.equals(that.condition);
    }

    @Override
    public int hashCode()
    { return Objects.hash(super.hashCode(), condition); }
}
