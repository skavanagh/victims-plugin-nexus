/**
 * Copyright 2014 Sean Kavanagh - sean.p.kavanagh6@gmail.com
 *
 * This code is distributed under the terms of the GNU Affero General
 * Public License (see <http://www.gnu.org/licenses/agpl.html>).
 */
package com.redhat.victims.nexus;

import javax.inject.Inject;
import javax.inject.Named;

import org.sonatype.configuration.ConfigurationException;
import org.sonatype.nexus.plugins.RepositoryCustomizer;
import org.sonatype.nexus.proxy.repository.ProxyRepository;
import org.sonatype.nexus.proxy.repository.Repository;
import org.sonatype.nexus.proxy.repository.RequestStrategy;

import com.google.common.base.Preconditions;


@Named(VictimsNexusScannerProcessor.NAME)
public class VictimsNexusScannerRepository
		implements RepositoryCustomizer {
	private final RequestStrategy processor;

	@Inject
	public VictimsNexusScannerRepository(final @Named(VictimsNexusScannerProcessor.NAME) RequestStrategy processor) {

		this.processor = Preconditions.checkNotNull(processor);
	}

	@Override
	public boolean isHandledRepository(final Repository repository) {

		return repository.getRepositoryKind().isFacetAvailable(ProxyRepository.class);

	}

	@Override
	public void configureRepository(final Repository repository) throws ConfigurationException {
		repository.registerRequestStrategy(VictimsNexusScannerProcessor.NAME, processor);
	}
}
