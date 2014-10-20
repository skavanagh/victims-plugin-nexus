/**
 * Copyright 2014 Sean Kavanagh - sean.p.kavanagh6@gmail.com
 *
 * This code is distributed under the terms of the GNU Affero General
 * Public License (see <http://www.gnu.org/licenses/agpl.html>).
 */
package com.redhat.victims.nexus;

import org.sonatype.nexus.proxy.item.StorageFileItem;
import org.sonatype.sisu.litmus.testsupport.TestSupport;

import org.junit.Before;
import org.junit.Test;

import java.io.FileInputStream;

import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


public class VictimsScannerTest
		extends TestSupport {
	private VictimsNexusScanner underTest;

	@Before
	public void setUp() throws Exception {
		underTest = new VictimsNexusScanner();
	}

	@Test
	public void passChecks() throws Exception {

		//setup
		StorageFileItem item = mock(StorageFileItem.class);

		String name = "struts2-core-2.3.16.3.jar";
		FileInputStream fis = new FileInputStream(getClass().getResource("/not_vulnerable/").getPath() + name);

		when(item.getName()).thenReturn(name);
		when(item.getInputStream()).thenReturn(fis);

		//checks
		assertThat(underTest.getFingerprintVulnerabilities(item).size(), is(0));
		assertThat(underTest.getMetadataVulnerabilities(item).size(), is(0));
	}

	@Test
	public void failFingerprintCheck() throws Exception {

		//setup
		StorageFileItem item = mock(StorageFileItem.class);

		String name = "struts2-core-2.3.12.jar";
		FileInputStream fis = new FileInputStream(getClass().getResource("/failed_fingerprint/").getPath() + name);

		when(item.getName()).thenReturn(name);
		when(item.getInputStream()).thenReturn(fis);

		//checks
		assertThat(underTest.getFingerprintVulnerabilities(item).size(), greaterThan(0));
	}

	@Test
	public void failMetadataCheck() throws Exception {

		//setup
		StorageFileItem item = mock(StorageFileItem.class);

		String name = "cxf-rt-ws-security-2.5.8.jar";
		FileInputStream fis = new FileInputStream(getClass().getResource("/failed_metadata/").getPath() + name);

		when(item.getName()).thenReturn(name);
		when(item.getInputStream()).thenReturn(fis);

		//checks
		assertThat(underTest.getMetadataVulnerabilities(item).size(), greaterThan(0));

	}
}
