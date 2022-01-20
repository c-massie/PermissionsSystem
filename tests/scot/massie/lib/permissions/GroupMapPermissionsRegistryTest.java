package scot.massie.lib.permissions;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.Test;
import scot.massie.lib.permissions.exceptions.MissingPermissionException;
import scot.massie.lib.permissions.exceptions.UserMissingPermissionException;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class GroupMapPermissionsRegistryTest extends PermissionsRegistryTest<GroupMapPermissionsRegistry<String>>
{
    /*

    Note: Tests that pass for users are expected to pass for groups as well, as they're both implemented using the same
    class. Providing test coverage for both would be needless duplication.

     */

    @Override
    protected GroupMapPermissionsRegistry<String> getNewPermissionsRegistry()
    { return new GroupMapPermissionsRegistry<>(s -> s, s -> s); }

    @Override
    protected void createUser(GroupMapPermissionsRegistry<String> reg, String userId)
    { reg.getUserPermissionsGroupOrNew(userId); }

    @Override
    protected void createGroup(GroupMapPermissionsRegistry<String> reg, String groupName)
    { reg.getGroupPermissionsGroupOrNew(groupName); }

    @Override
    protected void createGroup(GroupMapPermissionsRegistry<String> reg, String groupName, int priority)
    { reg.getGroupPermissionsGroupOrNew(groupName, priority); }

    @Override
    protected void createGroup(GroupMapPermissionsRegistry<String> reg, String groupName, double priority)
    { reg.getGroupPermissionsGroupOrNew(groupName, priority); }
}
