/**
 * Copyright 2014 Sean Kavanagh - sean.p.kavanagh6@gmail.com
 *
 * This code is distributed under the terms of the GNU Affero General
 * Public License (see <http://www.gnu.org/licenses/agpl.html>).
 */
package com.redhat.victims.nexus;

import org.sonatype.nexus.proxy.item.StorageFileItem;
import org.sonatype.sisu.goodies.eventbus.EventBus;
import org.sonatype.sisu.litmus.testsupport.TestSupport;

import com.google.common.collect.Lists;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;

import java.util.HashSet;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;


public class VictimsScannerProcessorTest
		extends TestSupport {
	private VictimsNexusScannerProcessor underTest;

	@Mock
	private EventBus eventBus;

	@Mock
	private VictimsNexusScanner scanner;


	@Before
	public void setUp() throws Exception {
		underTest = new VictimsNexusScannerProcessor(eventBus, Lists.newArrayList(scanner));
	}


	@Test
	public void vulnerabilityFingerprinted() {

		//setup
		StorageFileItem item = mock(StorageFileItem.class, RETURNS_DEEP_STUBS);

		HashSet<String> cves = new HashSet<String>();
		cves.add("CVE-XXXX-YYYY");

		when(scanner.getFingerprintVulnerabilities(any(StorageFileItem.class))).thenReturn(cves);

		//checks
		assertThat(underTest.getFingerprintVulnerabilities(item).size(), is(1));

		verify(scanner).getFingerprintVulnerabilities(item);
		verify(eventBus, times(1)).post(any(VulnerableItemFoundEvent.class));
	}

	@Test
	public void vulnerabilityMetadata() {

		//setup
		StorageFileItem item = mock(StorageFileItem.class, RETURNS_DEEP_STUBS);

		HashSet<String> cves = new HashSet<String>();
		cves.add("CVE-XXXX-YYYY");

		when(scanner.getMetadataVulnerabilities(any(StorageFileItem.class))).thenReturn(cves);

		//checks
		assertThat(underTest.getMetadataVulnerabilities(item).size(), is(1));

		verify(scanner).getMetadataVulnerabilities(item);
		verify(eventBus, times(1)).post(any(VulnerableItemFoundEvent.class));
	}

	@Test
	public void notVulnerable() {

		//setup
		StorageFileItem item = mock(StorageFileItem.class, RETURNS_DEEP_STUBS);

		when(scanner.getMetadataVulnerabilities(any(StorageFileItem.class))).thenReturn(new HashSet<String>());
		when(scanner.getFingerprintVulnerabilities(any(StorageFileItem.class))).thenReturn(new HashSet<String>());

		//checks
		assertThat(underTest.getMetadataVulnerabilities(item).size(), is(0));
		assertThat(underTest.getFingerprintVulnerabilities(item).size(), is(0));

		verify(scanner).getMetadataVulnerabilities(item);
		verify(scanner).getFingerprintVulnerabilities(item);
		verify(eventBus, times(0)).post(any(VulnerableItemFoundEvent.class));
	}
}
