import { Spinner, Strip } from "@canonical/react-components";

export default function Loading() {
	return (
		<Strip>
			<Spinner text="Loading..." />
		</Strip>
	);
}
