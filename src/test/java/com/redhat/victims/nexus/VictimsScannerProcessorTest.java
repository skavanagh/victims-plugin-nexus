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
		StorageFileItem item = mock(StorageFileItem.class, RETURNS_DEEP_STUBS);
		when(scanner.isVulnerableFingerprint(any(StorageFileItem.class))).thenReturn(true);
		assertThat(underTest.isVulnerableFingerprint(item), is(true));
		verify(scanner).isVulnerableFingerprint(item);
		verify(eventBus, times(1)).post(any(VulnerableItemFoundEvent.class));
	}

	@Test
	public void vulnerabilityMetadata() {
		StorageFileItem item = mock(StorageFileItem.class, RETURNS_DEEP_STUBS);
		when(scanner.isVulnerableMetadata(any(StorageFileItem.class))).thenReturn(true);
		assertThat(underTest.isVulnerableMetadata(item), is(true));
		verify(scanner).isVulnerableMetadata(item);
		verify(eventBus, times(1)).post(any(VulnerableItemFoundEvent.class));
	}
}
