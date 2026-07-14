use crate::IpProtocol;

/// Fragment position without any reassembly state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FragmentState {
    Unfragmented,
    First {
        more_fragments: bool,
    },
    NonFirst {
        offset_units: u16,
        more_fragments: bool,
    },
}

impl FragmentState {
    #[must_use]
    pub const fn offset_bytes(self) -> usize {
        match self {
            Self::Unfragmented | Self::First { .. } => 0,
            Self::NonFirst { offset_units, .. } => offset_units as usize * 8,
        }
    }

    #[must_use]
    pub const fn is_fragmented(self) -> bool {
        !matches!(self, Self::Unfragmented)
    }
}

/// Semantic L3 disposition of bytes after the final safely traversed header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpperLayerState<'a> {
    Reachable {
        protocol: IpProtocol,
        payload: &'a [u8],
        fragment: FragmentState,
    },
    Insufficient {
        protocol: IpProtocol,
        payload: &'a [u8],
        required: usize,
        fragment: FragmentState,
    },
    NonFirstFragment {
        protocol: IpProtocol,
        payload: &'a [u8],
        fragment: FragmentState,
    },
    Esp {
        payload: &'a [u8],
        fragment: FragmentState,
    },
    NoNextHeader {
        trailing: &'a [u8],
    },
    Unknown {
        protocol: IpProtocol,
        payload: &'a [u8],
        fragment: FragmentState,
    },
}

pub(crate) fn classify_upper_layer(
    protocol: IpProtocol,
    payload: &[u8],
    fragment: FragmentState,
    ipv6: bool,
) -> UpperLayerState<'_> {
    if let FragmentState::NonFirst { .. } = fragment {
        return UpperLayerState::NonFirstFragment {
            protocol,
            payload,
            fragment,
        };
    }
    match protocol.get() {
        50 => UpperLayerState::Esp { payload, fragment },
        59 if ipv6 => UpperLayerState::NoNextHeader { trailing: payload },
        1 | 6 | 17 | 58 => {
            let required = match protocol.get() {
                6 => 20,
                17 => 8,
                1 | 58 => 4,
                _ => 0,
            };
            if payload.len() < required {
                UpperLayerState::Insufficient {
                    protocol,
                    payload,
                    required,
                    fragment,
                }
            } else {
                UpperLayerState::Reachable {
                    protocol,
                    payload,
                    fragment,
                }
            }
        }
        _ => UpperLayerState::Unknown {
            protocol,
            payload,
            fragment,
        },
    }
}
