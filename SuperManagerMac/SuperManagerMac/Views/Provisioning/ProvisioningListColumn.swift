import SwiftUI

/// Middle column of the Provisioning section. Tree-style list of
/// customers with their sites nested underneath. Click a site to
/// open the render view in the detail column. Click a customer
/// (no site selected) to see the customer-edit affordances.
///
/// New-customer button at the bottom — keeping creation always
/// reachable instead of stuffed in a toolbar menu, since the
/// empty state needs an obvious next-action and the populated
/// state benefits from quick-create.
struct ProvisioningListColumn: View {
    @Environment(AppState.self) private var appState

    @State private var showingAddCustomer = false
    @State private var customerToEdit: Customer?
    @State private var showingDeleteConfirm = false
    @State private var customerPendingDelete: Customer?

    var body: some View {
        VStack(spacing: 0) {
            if appState.customers.isEmpty {
                emptyState
            } else {
                customerList
            }
            footer
        }
        .sheet(isPresented: $showingAddCustomer) {
            CustomerEditSheet(customer: nil)
        }
        .sheet(item: $customerToEdit) { customer in
            CustomerEditSheet(customer: customer)
        }
        .alert(
            "Delete customer?",
            isPresented: $showingDeleteConfirm,
            presenting: customerPendingDelete
        ) { customer in
            Button("Delete \(customer.displayName)", role: .destructive) {
                Task {
                    await appState.deleteCustomer(slug: customer.slug)
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: { customer in
            Text("Removes \(customer.sites.count) site\(customer.sites.count == 1 ? "" : "s") and all stored deployment history. SSH hosts and compliance runs are not deleted.")
        }
        .task {
            // Lazy-load templates on first activation so the
            // detail view's picker is hydrated.
            if appState.provisioningTemplates.isEmpty {
                await appState.loadProvisioningTemplates()
            }
        }
    }

    // MARK: - Empty state

    private var emptyState: some View {
        ContentUnavailableView {
            Label("No customers yet", systemImage: "building.2")
        } description: {
            Text("Customers group sites and supply the variables your provisioning templates reference (VLAN map, WAN type, contact info).")
        } actions: {
            Button {
                showingAddCustomer = true
            } label: {
                Label("Add customer…", systemImage: "plus")
            }
            .controlSize(.large)
            .buttonStyle(.borderedProminent)
        }
    }

    // MARK: - Customer list

    private var customerList: some View {
        List {
            ForEach(appState.customers) { customer in
                Section {
                    Button(action: {
                        appState.selectedCustomerSlug = customer.slug
                        appState.selectedSiteId = nil
                    }) {
                        HStack {
                            Image(systemName: "building.2.fill")
                                .foregroundStyle(.tint)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(customer.displayName)
                                    .fontWeight(.semibold)
                                Text("\(customer.sites.count) site\(customer.sites.count == 1 ? "" : "s")")
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            }
                            Spacer()
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .background(
                        RoundedRectangle(cornerRadius: 4)
                            .fill(
                                appState.selectedCustomerSlug == customer.slug && appState.selectedSiteId == nil
                                    ? Color.accentColor.opacity(0.15)
                                    : Color.clear
                            )
                    )
                    .contextMenu {
                        Button("Edit customer…") {
                            customerToEdit = customer
                        }
                        Divider()
                        Button("Delete…", role: .destructive) {
                            customerPendingDelete = customer
                            showingDeleteConfirm = true
                        }
                    }

                    ForEach(customer.sites) { site in
                        Button(action: {
                            appState.selectedCustomerSlug = customer.slug
                            appState.selectedSiteId = site.id
                        }) {
                            HStack {
                                Image(systemName: "mappin.and.ellipse")
                                    .foregroundStyle(.secondary)
                                    .font(.caption)
                                VStack(alignment: .leading, spacing: 0) {
                                    Text(site.displayName)
                                        .font(.callout)
                                    if !site.address.isEmpty {
                                        Text(site.address)
                                            .font(.caption2)
                                            .foregroundStyle(.tertiary)
                                            .lineLimit(1)
                                    }
                                }
                                Spacer()
                                if !site.vlans.isEmpty {
                                    Text("\(site.vlans.count) VLAN\(site.vlans.count == 1 ? "" : "s")")
                                        .font(.caption2)
                                        .foregroundStyle(.tertiary)
                                }
                            }
                            .padding(.leading, 16)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .background(
                            RoundedRectangle(cornerRadius: 4)
                                .fill(
                                    appState.selectedCustomerSlug == customer.slug && appState.selectedSiteId == site.id
                                        ? Color.accentColor.opacity(0.15)
                                        : Color.clear
                                )
                        )
                    }
                }
            }
        }
        .listStyle(.sidebar)
    }

    // MARK: - Footer

    private var footer: some View {
        HStack {
            Button {
                showingAddCustomer = true
            } label: {
                Label("Add customer", systemImage: "plus")
            }
            .controlSize(.small)
            Spacer()
        }
        .padding(8)
        .background(.background.secondary)
    }
}
