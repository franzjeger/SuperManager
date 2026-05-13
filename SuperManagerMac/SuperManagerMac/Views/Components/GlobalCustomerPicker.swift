import SwiftUI

/// Compact toolbar control that scopes the entire app to a single
/// customer. Persisted across launches via `@AppStorage`. When set,
/// every section (SSH/Compliance/Provisioning/Security/Fleet) reads
/// `appState.globalCustomerSlug` and filters their lists to records
/// belonging to that customer.
///
/// "All customers" (empty slug) is the default — keeps the previous
/// global-view behaviour as a one-click escape hatch.
struct GlobalCustomerPicker: View {
    @Environment(AppState.self) private var appState
    @AppStorage("globalCustomerSlug") private var persistedSlug: String = ""

    var body: some View {
        Menu {
            Button {
                set(slug: "")
            } label: {
                Label("All customers", systemImage: appState.globalCustomerSlug.isEmpty ? "checkmark" : "")
            }
            if !appState.customers.isEmpty {
                Divider()
                ForEach(appState.customers) { c in
                    Button {
                        set(slug: c.slug)
                    } label: {
                        Label(
                            c.displayName,
                            systemImage: appState.globalCustomerSlug == c.slug ? "checkmark" : ""
                        )
                    }
                }
            }
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "building.2")
                    .accessibilityHidden(true)
                Text(currentLabel)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Image(systemName: "chevron.up.chevron.down")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .accessibilityHidden(true)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(.background.secondary)
            .clipShape(RoundedRectangle(cornerRadius: 6))
        }
        .menuStyle(.button)
        .buttonStyle(.borderless)
        .accessibilityLabel("Customer filter: \(currentLabel)")
        .help("Filter the entire app to one customer's hosts, engagements, and findings. \"All customers\" disables the filter.")
        .task {
            // Hydrate AppState from the persisted value on first appear.
            if appState.globalCustomerSlug != persistedSlug {
                appState.globalCustomerSlug = persistedSlug
            }
        }
    }

    private var currentLabel: String {
        if appState.globalCustomerSlug.isEmpty {
            return "All customers"
        }
        if let c = appState.customers.first(where: { $0.slug == appState.globalCustomerSlug }) {
            return c.displayName
        }
        return appState.globalCustomerSlug
    }

    private func set(slug: String) {
        appState.globalCustomerSlug = slug
        persistedSlug = slug
    }
}

#if DEBUG
#Preview("All customers") {
    GlobalCustomerPicker()
        .environment(AppState.previewSeeded)
        .padding()
}

#Preview("Acme selected") {
    let s = AppState.previewSeeded
    s.globalCustomerSlug = "acme-corp"
    return GlobalCustomerPicker()
        .environment(s)
        .padding()
}
#endif
