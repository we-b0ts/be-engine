//! Seek over immutable pages and a few session-only rows without opening skipped pages.
use super::*;

enum Segment<'a> {
    Page(usize),
    Extra(&'a Row),
}

fn append<'a>(
    segments: &mut Vec<(usize, Segment<'a>)>,
    total: &mut usize,
    count: usize,
    segment: Segment<'a>,
) -> Result<()> {
    if count > 0 {
        *total = total
            .checked_add(count)
            .context("Global cursor count overflow")?;
        segments.push((*total, segment));
    }
    Ok(())
}

pub(super) fn read(
    evidence: &RegularEvidence,
    report: &Path,
    offset: usize,
    limit: usize,
    items: &mut Vec<Value>,
) -> Result<()> {
    let (inventory, root) = evidence.load(report)?;
    ensure!(
        offset <= evidence.remaining,
        "Global detail offset exceeds count"
    );
    if offset == evidence.remaining || items.len() >= limit {
        return Ok(());
    }
    let changes = evidence
        .changes
        .iter()
        .map(|change| (change.position, change.after))
        .collect::<BTreeMap<_, _>>();
    let visible = |row: &Row| changes.get(&row.position).copied().unwrap_or(row.visible);
    let mut adjustment = 0i128;
    let adjustments = evidence
        .changes
        .iter()
        .map(|change| {
            adjustment += if change.after { 1 } else { -1 };
            (change.position, adjustment)
        })
        .collect::<Vec<_>>();
    let prefix = |position: Position, inclusive: bool| {
        let count = adjustments.partition_point(|(key, _)| {
            if inclusive {
                *key <= position
            } else {
                *key < position
            }
        });
        if count == 0 {
            0
        } else {
            adjustments[count - 1].1
        }
    };
    let mut segments = Vec::new();
    let mut total = 0usize;
    let mut extras = evidence.extras.iter().peekable();
    for (index, page) in inventory.pages.iter().enumerate() {
        while extras
            .peek()
            .is_some_and(|extra| extra.position < page.first)
        {
            let extra = extras.next().unwrap();
            append(
                &mut segments,
                &mut total,
                usize::from(visible(extra)),
                Segment::Extra(extra),
            )?;
        }
        ensure!(
            extras.peek().is_none_or(|extra| extra.position > page.last),
            "session-only Global row overlaps immutable inventory page"
        );
        let count = usize::try_from(
            page.visible as i128 + prefix(page.last, true) - prefix(page.first, false),
        )
        .context("Global cursor visibility underflow")?;
        ensure!(
            count <= page.count,
            "Global cursor visibility exceeds page size"
        );
        append(&mut segments, &mut total, count, Segment::Page(index))?;
    }
    for extra in extras {
        append(
            &mut segments,
            &mut total,
            usize::from(visible(extra)),
            Segment::Extra(extra),
        )?;
    }
    ensure!(
        total == evidence.remaining,
        "Global cursor does not cover the complete session inventory"
    );
    let start = segments.partition_point(|(end, _)| *end <= offset);
    let mut skip = offset - if start == 0 { 0 } else { segments[start - 1].0 };
    for (_, segment) in segments.into_iter().skip(start) {
        let rows = match segment {
            Segment::Page(index) => inventory.read_page(&root, index)?,
            Segment::Extra(row) => vec![row.clone()],
        };
        for row in rows {
            if !visible(&row) {
                continue;
            }
            if skip > 0 {
                skip -= 1;
                continue;
            }
            items.push(row.value);
            if items.len() == limit {
                return Ok(());
            }
        }
    }
    Ok(())
}
