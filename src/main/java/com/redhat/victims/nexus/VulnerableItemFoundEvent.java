/**
 * Copyright 2014 Sean Kavanagh - sean.p.kavanagh6@gmail.com
 *
 * This code is distributed under the terms of the GNU Affero General
 * Public License (see <http://www.gnu.org/licenses/agpl.html>).
 */
package com.redhat.victims.nexus;

import org.sonatype.nexus.events.AbstractEvent;
import org.sonatype.nexus.proxy.item.StorageFileItem;
import org.sonatype.nexus.proxy.repository.Repository;

import static com.google.common.base.Preconditions.checkNotNull;


public class VulnerableItemFoundEvent
		extends AbstractEvent<Repository> {
	private final StorageFileItem item;

	public VulnerableItemFoundEvent(final Repository repository, final StorageFileItem item) {
		super(repository);
		this.item = checkNotNull(item);
	}

	public Repository getRepository() {
		return getEventSender();
	}

	public StorageFileItem getItem() {
		return item;
	}

}
