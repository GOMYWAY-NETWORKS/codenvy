/*
 * CODENVY CONFIDENTIAL
 * __________________
 *
 *  [2012] - [2014] Codenvy, S.A.
 *  All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Codenvy S.A. and its suppliers,
 * if any.  The intellectual and technical concepts contained
 * herein are proprietary to Codenvy S.A.
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Codenvy S.A..
 */
package com.codenvy.organization.dao.mongo;

import com.codenvy.api.user.server.dao.UserDao;
import com.codenvy.api.user.server.dao.UserProfileDao;
import com.codenvy.api.user.server.exception.ProfileNotFoundException;
import com.codenvy.api.user.server.exception.UserProfileException;
import com.codenvy.api.user.shared.dto.Attribute;
import com.codenvy.api.user.shared.dto.Profile;
import com.codenvy.dto.server.DtoFactory;
import com.mongodb.BasicDBObject;
import com.mongodb.DBObject;
import com.mongodb.util.JSON;

import org.mockito.Mock;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.w3c.dom.Attr;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.*;

/**
 *
 */
@Listeners(value = {MockitoTestNGListener.class})
public class UserProfileDaoTest extends BaseDaoTest {
    @Mock
    private UserDao userDao;
    private static final String COLL_NAME = "profile";
    UserProfileDao profileDao;

    private static final String PROFILE_ID = "profile123abc456def";
    private static final String USER_ID    = "user123abc456def";


    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp(COLL_NAME);
        profileDao = new UserProfileDaoImpl(userDao, db, COLL_NAME);
    }

    @AfterMethod
    public void tearDown() throws Exception {
        super.tearDown();
    }

    @Test
    public void mustSaveProfile() throws Exception {
        Profile profile = DtoFactory.getInstance().createDto(Profile.class).withId(PROFILE_ID).withUserId(USER_ID)
                                    .withAttributes(getAttributes());

        // main invoke
        profileDao.create(profile);

        DBObject res = collection.findOne(new BasicDBObject("id", PROFILE_ID));
        assertNotNull(res, "Specified user profile does not exists.");

        Profile result =
                DtoFactory.getInstance().createDtoFromJson(res.toString(), Profile.class);
        assertEquals(profile.getLinks(), result.getLinks());
        assertEquals(profile, result);
    }

    @Test
    public void mustGetProfileByIdWithPreferencesFilter() throws UserProfileException {
        Map<String, String> prefs = new HashMap<>();
        prefs.put("first", "first_value");
        prefs.put("____firstASD", "other_first_value");
        prefs.put("second", "second_value");
        prefs.put("other", "other_value");

        Profile tmp = DtoFactory.getInstance().createDto(Profile.class)
                                .withId(PROFILE_ID)
                                .withUserId(USER_ID)
                                .withAttributes(Collections.<Attribute>emptyList())
                                .withPreferences(prefs);

        collection.save((DBObject)JSON.parse(tmp.toString()));

        Profile profile = profileDao.getById(PROFILE_ID, ".*first.*");
        assertNotNull(profile);
        Map<String, String> expectedPrefs = new HashMap<>();
        expectedPrefs.put("first", "first_value");
        expectedPrefs.put("____firstASD", "other_first_value");
        assertEquals(expectedPrefs, profile.getPreferences());

        profile = profileDao.getById(PROFILE_ID, "other");
        assertNotNull(profile);
        expectedPrefs.clear();
        expectedPrefs.put("other", "other_value");
        assertEquals(expectedPrefs, profile.getPreferences());
    }

    @Test
    public void mustNotUpdateProfileIfNotExist() throws Exception {

        Profile profile = DtoFactory.getInstance().createDto(Profile.class).withId(PROFILE_ID).withUserId(USER_ID)
                                    .withAttributes(getAttributes());
        try {
            profileDao.update(profile);
            fail("Update of non-existing profile prohibited.");
        } catch (ProfileNotFoundException e) {
            // OK
        }
    }

    @Test
    public void mustRemoveProfile() throws Exception {
        DBObject obj = new BasicDBObject("id", PROFILE_ID).append("userid", USER_ID);
        collection.insert(obj);

        DBObject query = new BasicDBObject("id", PROFILE_ID);
        profileDao.remove(PROFILE_ID);

        assertNull(collection.findOne(query));
    }


    private List<Attribute> getAttributes() {
        List<Attribute> attributes = new ArrayList<>();
        attributes.add(DtoFactory.getInstance().createDto(Attribute.class).withName("attr1").withValue("value1")
                                 .withDescription("description1"));
        attributes.add(DtoFactory.getInstance().createDto(Attribute.class).withName("attr2").withValue("value2")
                                 .withDescription("description2"));
        attributes.add(DtoFactory.getInstance().createDto(Attribute.class).withName("attr3").withValue("value3")
                                 .withDescription("description3"));
        return attributes;
    }
}
