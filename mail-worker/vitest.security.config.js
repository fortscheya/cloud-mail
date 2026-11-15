import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config';

export default defineWorkersConfig({
	test: {
		include: ['tests/security.test.js'],
		poolOptions: {
			workers: {
				singleWorker: true,
				miniflare: {
					compatibilityDate: '2025-06-04',
					kvNamespaces: ['kv'],
					d1Databases: ['db'],
				},
			},
		},
	},
});
